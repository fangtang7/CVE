# Solon WebDAV Arbitrary File Reading Vulnerability Report

## Vulnerability Description

The `solon-web-webdav` module of the Solon framework provides support for the WebDAV file system. The `realPath()` method in the `LocalFileSystem` implementation directly concatenates the user-controllable path parameters with the root path, without any filtering of `../`. An attacker can traverse the path to read, write, and delete arbitrary files on the serve。

---

## Affected Versions

The latest version of the Solon framework [Solon v4.0.4](https://gitee.com/opensolon/solon/releases/tag/v4.0.4)

（All versions using the solon-web-webdav module）

---

## Utilize conditions

- The application utilizes the `solon-web-webdav` module
- - the WebDAV endpoint is exposed

---

## Vulnerability Reproduction

**File path**：`solon-projects/solon-web/solon-web-webdav/src/main/java/org/noear/solon/web/webdav/impl/LocalFileSystem.java`
**line number**：47-52

Direct concatenation of paths, without any filtering of ../

![image-20260803231237499](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231237499.6po824pc0v.webp)

Line numbers: 89-96 — The fileInfo() method receives the path requested by the user

![image-20260803231339483](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231339483.5flavt81vd.webp)

Line numbers: 129-131 — FileUtil.getInputStream() reads a file and returns a stream

![image-20260803231432875](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231432875.7p4bfatagn.webp)

**Request package**：

```
GET /../../../../../../../../windows/win.ini HTTP/1.1
Host: localhost:8085
Connection: keep-alive
```

![image-20260803231510669]([C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803231510669.png](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231510669.icu1yv8oj.webp))
