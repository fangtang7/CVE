# Xinguan JWT Password-Hash-As-Key Forgery Vulnerability Report

## Introduction to Vulnerabilities

The authentication of Xinguan (an open-source material-management system) uses the user's own password hash as the HMAC256 signing key of the stateless JWT token. `UserRealm.java` verifies each request with `JWTUtils.verify(token, username, userBean.getPassword())` — the "secret" is the password hash stored in `tb_user` (MD5 ×1024 iterations + salt). The official SQL seed file `document/xinguan.sql` publishes the default admin hash (`d7b9c28cac022955cff27947eafce0ad`, salt `cfbf6d34-d3e4-4653-86f0-e33d4595d52b`, `type=0` full-permission user). The signing key is therefore publicly derivable: an attacker signs `{"username":"admin"}` offline with the published hash and the server accepts it as a legitimate superadmin session — **zero password verification, no login required**. Beyond the default value, the design itself is broken: for any user, a leaked hash *is* the key — account takeover without ever cracking the plaintext.

---

## Affected Versions

Xinguan (all current versions / master; authentication code and SQL seed unchanged since 2020)

## Utilize conditions

- The target is initialized with the official `xinguan.sql` seed and the default admin password unchanged (the documented deployment workflow)
- All routes pass through the JWT filter (`/**`), only `/system/user/login`, `/user/imgCode`, swagger, static and druid are whitelisted — no second line of defense
- The login captcha (`/user/imgCode`) is generated but never verified anywhere in the codebase; no login rate limit or lockout

---

## Vulnerability Reproduction

The front-end accepts the token via the `Authorization` header:

Before executing the JWT forgery (request without token is rejected):

![image-20260817163939451](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817163939451.8dxlixclic.webp)

Executing the forged-token request — the token was signed offline with the publicly published admin password hash `d7b9c28cac022955cff27947eafce0ad` as the HMAC256 secret, and the server returns the admin profile (`isAdmin:true`):

![image-20260817164057239](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817164057239.2ksn9mpnn6.webp)

![image-20260817164044066](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817164044066.2h91bwx984.webp)

In the `UserRealm.java` file, the JWT signing key is the user's own password hash — a leaked hash equals a forgeable token:

![image-20260817164156629](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817164156629.73uoclw6p5.webp)

`JWTUtils.java` signs/verifies with HMAC256 using that hash as the secret:

![image-20260817164239131](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817164239131.5trr6aemca.webp)

The SQL seed publishes the default admin hash (the "key" is public):

![image-20260817164420233](https://github.com/fangtang7/picx-images-hosting/raw/master/Xinguan/image-20260817164420233.51evojydvb.webp)

Forgery script (stdlib only): sign header/payload `{"username":"admin","exp":...}` with the hash as secret, then:

```http
GET /system/user/info HTTP/1.1
Host: <target:8989>
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzg2OTc3NjAxfQ.hIcICMdwgnTS11YPhrZEpLaVXtKQ_WVRtB4rRDa7CKo
```

Response:

```json
{"success":true,"data":{"username":"admin","nickname":"小章鱼","department":"物资管理部","isAdmin":true}}
```

Arbitrary user impersonation: the same procedure with any other leaked hash (e.g. seed user `jack`, hash `49bdaf7293cc9bd6fc9f50c3b03b7d6d`) reads/writes that account's data; `GET /system/user/findUserList` with the admin token returns the full user list.

**Evidence chain**

| #    | File:line                                         | Evidence                                                     |
| ---- | ------------------------------------------------- | ------------------------------------------------------------ |
| 1    | `xinguan-system/.../shiro/UserRealm.java:96`      | `JWTUtils.verify(token, username, userBean.getPassword())` — signing key = user's password hash |
| 2    | `xinguan-common/.../utils/JWTUtils.java:25-40`    | `Algorithm.HMAC256(secret)` — HMAC256 with that hash as secret |
| 3    | `document/xinguan.sql:381`                        | Default admin hash `d7b9c28cac022955cff27947eafce0ad` + salt `cfbf6d34-d3e4-4653-86f0-e33d4595d52b` + `type=0` |
| 4    | `xinguan-system/.../shiro/UserRealm.java:73-74`   | `type=0` users granted `*:*` full permissions                |
| 5    | `xinguan-system/.../shiro/ShiroConfig.java:46-52` | `/**` → JWT filter (single line of defense); `/user/imgCode` whitelisted |
| 6    | `/user/imgCode`                                   | Captcha generated but never checked project-wide; no lockout/rate limit |

**Fix suggestion**

1. Replace the JWT signing key with a deployment-random secret (env/config, ≥256-bit) — never any user-derived value.
2. Remove the default admin hash from the SQL seed; force password change on first login.
3. Enforce the captcha and add login rate limiting/lockout.
4. Bind tokens to a credential version (invalidate on password change / logout).
