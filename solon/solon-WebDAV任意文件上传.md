# Solon WebDAV 任意文件上传漏洞报告

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

![image-20260803232008631](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803232008631.png)

行号: 140-143 — putFile() 方法接收用户请求的路径和文件内容

![image-20260803232034997](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803232034997.png)

**请求包**：

```
PUT /../../../../../../../../tmp/poc_test.jsp HTTP/1.1
Host: localhost:8085
Connection: keep-alive
```

![image-20260803232243672](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803232243672.png)