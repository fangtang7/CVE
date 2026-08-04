# Solon WebDAV Arbitrary File Upload Vulnerability Report

## Vulnerability Description

The `solon-web-webdav` module of the Solon framework provides support for the WebDAV file system. The `realPath()` method in the `LocalFileSystem` implementation directly concatenates the user-controllable path parameters with the root path, without any filtering of `../`. An attacker can traverse the path to read, write, and delete arbitrary files on the server。

---

## Affected Versions

The latest version of the Solon framework [Solon v4.0.4](https://gitee.com/opensolon/solon/releases/tag/v4.0.4)

(All versions using the solon-web-webdav module)

---

## Utilize conditions

- The application uses the `solon-web-webdav` module
- WebDAV endpoint is exposed - the application uses the `solon-web-webdav` module

---

## Vulnerability Reproduction

**File path**：`solon-projects/solon-web/solon-web-webdav/src/main/java/org/noear/solon/web/webdav/impl/LocalFileSystem.java`
**line number**：47-52

Direct concatenation of paths, without any filtering of ../

![image-20260803232008631](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803232008631.5c1oy3isfo.webp)

Line numbers: 140-143 — The putFile() method receives the path and file content requested by the user

![image-20260803232034997](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803232034997.67y6djsvzc.webp)

**Request package**：

```
PUT /../../../../../../../../tmp/poc_test.jsp HTTP/1.1
Host: localhost:8085
Connection: keep-alive
```

![image-20260803232243672](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803232243672.26m6z5p4zd.webp)
