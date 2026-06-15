# CLAUDE.md — Java 17 Spring Boot 2.7 Enterprise HTTPS Crypto Demo (Non-PQC)

## Goal (5-minute demo)
Build a **realistic enterprise-style** Java 17 Spring Boot 2.7 server that:
- serves **HTTPS** only using a **self-signed certificate** on port **8443**
- exposes:
  - `GET https://localhost:8443/hello`
  - `GET https://localhost:8443/crypto/capabilities`
- uses ONLY standard Java/Spring Boot TLS (no custom crypto code, no PQC)
- includes a script `scripts/client-demo.sh` that shows the **actual TLS crypto** used

This is the **"before" snapshot** of a typical enterprise Java app — the kind that's been running in production for 5-10 years. The code deliberately uses **verbose, pre-Java-17 enterprise patterns** so that the modernization path toward Java 25 (records, pattern matching, PQC) is visually compelling.

---

## Constraints
- Java: **17** (source/target), but code written in **Java 8/11 enterprise style**
- Framework: **Spring Boot 2.7.18** (javax.* namespace — pre-Jakarta EE 9)
- TLS: self-signed certificate, **TLS 1.2 only** (realistic legacy config)
- No custom crypto implementation
- Enterprise patterns: layered architecture, verbose POJOs, interface+impl services

---

## Enterprise Legacy Code Patterns

These patterns are **intentionally old-fashioned** to create clear modernization contrast:

| Pattern Used (Legacy) | Modernized Equivalent (Java 25) |
|---|---|
| Verbose POJOs: private fields, getters, setters, equals, hashCode, toString | `record` (1 line) |
| `instanceof` + explicit cast | Pattern matching for `instanceof` |
| if-else chains for type checks | `switch` expressions with pattern matching |
| `new ArrayList<>()` + for-loop + `.add()` | `List.of()`, streams, `Stream.toList()` |
| `javax.*` namespace (Spring Boot 2.7) | `jakarta.*` namespace (Spring Boot 3+) |
| Field `@Autowired` injection | Constructor injection |
| Interface + `*Impl` service pattern | Direct `@Service` class |
| No `var` — fully explicit types everywhere | `var` where appropriate |
| `new HashMap<>()` + `.put()` chains | `Map.of()`, record constructors |
| `Logger` boilerplate in every class | Same (but less surrounding boilerplate) |
| `javax.servlet.Filter` with javax.servlet.* imports | `jakarta.servlet.*` namespace |
| Custom `X509TrustManager` with `instanceof` + cast for key types | Pattern matching; handle PQC key types (ML-DSA) |
| `SSLContext.getInstance("TLSv1.2")` — hardcoded protocol | `SSLContext.getInstance("TLS")` — negotiate highest available |
| `Security.setProperty()` with classical-only algorithm lists | Include PQC named groups (x25519_ml-kem-768) |

---

## Migration Challenges (Java 17 → Java 25)

This section documents the **specific migration blockers** embedded in this codebase and how they relate to typical enterprise scenarios. Each challenge is deliberately present to make the modernization story realistic.

### Challenge 1: javax.* → jakarta.* Namespace Migration

**File:** `filter/RequestLoggingFilter.java`

**What it does:** A servlet filter that logs every HTTP request with timing. Uses `javax.servlet.Filter`, `javax.servlet.http.HttpServletRequest`, etc.

**Why it's hard in enterprise:**
- Spring Boot 3.x requires `jakarta.servlet.*` — the javax namespace is gone entirely. This is not backward-compatible.
- A simple search-and-replace of imports works for YOUR code. But every JAR on the classpath that touches the Servlet API must ALSO be Jakarta-compatible. If a single dependency (internal library, vendor SDK, legacy adapter) still references `javax.servlet`, you get `ClassNotFoundException` at runtime.
- Enterprise apps typically have 50-200 transitive dependencies. Auditing all of them for Jakarta compatibility is the bulk of the migration work.
- Some proprietary or vendor-provided JARs have no Jakarta version and require replacement or forking.

**Relation to PQC:** Indirect — you can't get to Spring Boot 3 (and its improved TLS 1.3 / PQC defaults) until the namespace migration is done. The namespace is the gate.

### Challenge 2: Hardcoded TLS 1.2 in Custom SSLContext

**File:** `config/SslConfig.java`

**What it does:** Creates a custom `SSLContext` hardcoded to `TLSv1.2` and a custom `X509TrustManager` that wraps the default with audit logging. Configures a `RestTemplate` bean for outbound HTTPS calls.

**Why it's hard in enterprise:**
- `SSLContext.getInstance("TLSv1.2")` prevents the JVM from negotiating TLS 1.3, which is required for PQC hybrid key exchange (ML-KEM). The fix is `SSLContext.getInstance("TLS")` — but security teams resist because they want explicit protocol control.
- The custom `TrustManager` inspects certificate chains using `instanceof RSAPublicKey` and `instanceof ECPublicKey`. When Java 25 introduces ML-DSA certificates, these checks don't recognize the new key types — they fall through to keySize=0. Not a crash, but a compliance gap in audit logs.
- Enterprise security teams often mandate specific TLS configurations. Changing from "TLSv1.2 only" to "TLS 1.3 with PQC" requires security review, penetration testing, and change management approval.
- Outbound client SSL configuration is copy-pasted across dozens of microservices. Each one must be updated independently.

**Relation to PQC:** Direct — this code is the #1 blocker for PQC key exchange. Even if the JVM supports ML-KEM, hardcoded TLS 1.2 prevents it from being negotiated.

### Challenge 3: Hardcoded Security Properties

**File:** `PqcDemoApplication.java`

**What it does:** Sets `jdk.tls.disabledAlgorithms` and `jdk.tls.namedGroups` via `Security.setProperty()` at application startup. Restricts TLS to classical algorithms only.

**Why it's hard in enterprise:**
- The `jdk.tls.namedGroups` property explicitly lists classical ECDHE curves (secp256r1, secp384r1, etc.). On Java 25, PQC hybrid groups (e.g., `x25519_ml-kem-768`) exist but won't be negotiated unless added to this list.
- These properties are often set in the JVM's `java.security` file, which is deployed to every server. Changing it requires coordination across infrastructure, security, and application teams.
- Enterprises with SOC2/PCI compliance have security policies that dictate exactly which algorithms are allowed. Adding PQC algorithms to the approved list requires policy updates, security reviews, and audit sign-off.
- If the enterprise uses a FIPS-validated JCE provider (e.g., Bouncy Castle FIPS), PQC algorithms may not be FIPS-certified yet, creating a compliance deadlock.

**Relation to PQC:** Direct — even on Java 25, PQC groups won't be negotiated if the named groups list doesn't include them. This is the "configuration-level" PQC blocker.

### Challenge 4: Language-Level Verbosity (Existing)

**Files:** All `model/*.java` POJOs, `service/*Impl.java`, controllers

**What it does:** Uses verbose Java 8/11 patterns — POJOs with getters/setters/equals/hashCode, `instanceof` + explicit cast, `new ArrayList<>()` + for-loops, field `@Autowired`, interface+impl services.

**Why it's hard in enterprise:**
- It's not *technically* hard — Records, pattern matching, and `var` are drop-in improvements. But enterprise code has thousands of these patterns across hundreds of files.
- Automated migration tools (OpenRewrite, IntelliJ refactoring) can handle much of this, but they require validation, testing, and code review for each change.
- Some patterns (interface+impl services) are enforced by architectural guidelines or framework requirements. Removing them requires policy changes, not just code changes.
- Teams must agree on the new style — should everything be a Record? When is `var` appropriate? This creates process friction beyond the technical change.

**Relation to PQC:** Indirect — verbose code makes the codebase harder to audit for crypto patterns. When you're searching for "every place we create an SSLContext" to update for PQC, 10,000 lines of boilerplate make the search harder.

### Summary: Migration Dependency Chain

```
Language modernization (Challenge 4)
  ↓ enables cleaner code for...
Namespace migration (Challenge 1: javax → jakarta)
  ↓ unblocks...
Framework upgrade (Spring Boot 2.7 → 3.x)
  ↓ enables...
TLS configuration update (Challenge 2: TLS 1.2 → 1.3)
  ↓ enables...
Security policy update (Challenge 3: add PQC named groups)
  ↓ enables...
PQC key exchange and certificates (ML-KEM, ML-DSA)
```

Each step has its own stakeholders, review process, and risk profile. This is why PQC migration in enterprise takes months, not days.

---

## Repository Layout
```
.
├── CLAUDE.md
├── README.md
├── pom.xml
├── src/main/java/com/example/pqcdemo/
│   ├── PqcDemoApplication.java                    (+ Security.setProperty hardening)
│   ├── controller/
│   │   ├── HelloController.java
│   │   └── CryptoCapabilitiesController.java
│   ├── filter/
│   │   └── RequestLoggingFilter.java               (javax.servlet.Filter — namespace blocker)
│   ├── service/
│   │   ├── CryptoCapabilitiesService.java          (interface)
│   │   └── CryptoCapabilitiesServiceImpl.java      (implementation)
│   ├── model/
│   │   ├── CryptoCapabilitiesResponse.java         (top-level response POJO)
│   │   ├── RuntimeInfo.java                        (POJO)
│   │   ├── CertificateInfo.java                    (POJO)
│   │   └── SecurityProviderInfo.java               (POJO)
│   └── config/
│       ├── KeystoreConfig.java                     (@Configuration)
│       └── SslConfig.java                          (custom TrustManager + TLS 1.2 lock)
├── src/main/resources/
│   └── application.properties
├── scripts/
│   ├── client-demo.sh
│   └── util.sh
└── tls/
    ├── server-keystore.p12
    └── server-cert.pem
```

---

## Build Configuration (pom.xml)

Spring Boot 2.7.18 with:
- `spring-boot-starter-parent` 2.7.18
- `spring-boot-starter-web` (embedded Tomcat)
- `spring-boot-starter-test` (test scope)
- `maven.compiler.source` / `target` = 17
- No additional dependencies (Jackson is included via starter-web)

---

## HTTPS / Self-signed certificate

### Keystore (checked into repo under ./tls)

```bash
keytool -genkeypair \
  -alias server \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore tls/server-keystore.p12 \
  -storepass changeit \
  -dname "CN=localhost, OU=Dev, O=Demo, L=Zurich, ST=ZH, C=CH" \
  -validity 3650 \
  -ext "SAN=dns:localhost,ip:127.0.0.1"

keytool -exportcert \
  -alias server \
  -keystore tls/server-keystore.p12 \
  -storepass changeit \
  -rfc \
  -file tls/server-cert.pem
```

RSA-2048 for maximum "enterprise typical" familiarity.

### Spring Boot HTTPS configuration (application.properties)

```properties
server.port=8443
server.ssl.key-store=file:tls/server-keystore.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12
server.ssl.enabled-protocols=TLSv1.2
```

- Port **8443** (enterprise-standard HTTPS)
- **TLS 1.2 only** — intentionally legacy; contrasts with TLS 1.3 on modernized branch
- No cipher suite restrictions (use JVM defaults)
- HTTP is not exposed (Spring Boot only binds HTTPS when SSL is configured)

---

## Java Source Code Spec

### PqcDemoApplication.java
Standard `@SpringBootApplication` main class.

### controller/HelloController.java
- `@RestController`
- `@GetMapping("/hello")` returns plain text `"hello world"`

### controller/CryptoCapabilitiesController.java
- `@RestController`
- `@GetMapping("/crypto/capabilities")` delegates to service, returns JSON
- Uses field `@Autowired` (legacy pattern)
- Has a `private static final Logger` (SLF4J)

### service/CryptoCapabilitiesService.java
- Interface with single method: `CryptoCapabilitiesResponse getCapabilities()`

### service/CryptoCapabilitiesServiceImpl.java
- `@Service` implementing the interface
- Uses field `@Autowired` for `KeystoreConfig`
- Contains all crypto introspection logic:
  - `SSLContext.getDefault()` for TLS protocols/ciphers
  - `KeyStore` loading for certificate details
  - `Security.getProviders()` for provider listing
  - PQC algorithm scan across all providers
- Written in verbose style:
  - Explicit `for` loops, no streams
  - `instanceof` + cast (no pattern matching)
  - `new ArrayList<>()` with `.add()` calls
  - Full try-catch blocks

### model/CryptoCapabilitiesResponse.java
Top-level response POJO containing:
- `RuntimeInfo runtime`
- `List<SecurityProviderInfo> securityProviders`
- `Map<String, Object> tls` (TLS details as map — protocols, ciphers, named groups)
- `CertificateInfo serverCertificate`
- `Map<String, Object> pqc` (PQC status as map)

Full POJO: no-arg constructor, all-args constructor, getters, setters, toString, equals, hashCode.

### model/RuntimeInfo.java
Fields: `javaVersion`, `javaVendor`, `javaVmName`, `osName`, `osArch` (all String).
Full POJO with all boilerplate.

### model/CertificateInfo.java
Fields: `subject`, `issuer`, `notBefore`, `notAfter`, `publicKeyAlgorithm` (String), `publicKeySizeBits` (int), `signatureAlgorithm` (String), `san` (List<String>).
Full POJO with all boilerplate.

### model/SecurityProviderInfo.java
Fields: `name`, `version`, `info` (all String).
Full POJO with all boilerplate.

### config/KeystoreConfig.java
- `@Configuration` class
- Reads keystore path, password, alias from `application.properties` via `@Value`
- Provides getter methods for the service to use

### config/SslConfig.java
- `@Configuration` class
- Creates hardcoded `SSLContext.getInstance("TLSv1.2")` (blocks PQC key exchange)
- Wraps default `X509TrustManager` with audit logging (`AuditTrustManager` inner class)
  - Logs certificate chain details using `instanceof` + cast (RSAPublicKey, ECPublicKey)
  - Does not recognize PQC key types — migration gap
- Exposes a `RestTemplate` `@Bean` configured with the custom SSLContext

### filter/RequestLoggingFilter.java
- `javax.servlet.Filter` implementation (namespace migration blocker)
- `@Component` + `@Order(1)` for auto-registration
- Logs: HTTP method, URI, response status, duration in ms
- Uses `javax.servlet.http.HttpServletRequest` / `HttpServletResponse`

---

## REST API Spec

### GET /hello
- Response: `text/plain`: `hello world`
- Served over HTTPS only: `https://localhost:8443/hello`

### GET /crypto/capabilities
Return JSON (same structure as before):

```json
{
  "runtime": {
    "javaVersion": "...",
    "javaVendor": "...",
    "javaVmName": "...",
    "osName": "...",
    "osArch": "..."
  },
  "securityProviders": [
    { "name": "...", "version": "...", "info": "..." }
  ],
  "tls": {
    "defaultSslContextProvider": "...",
    "supportedProtocols": ["TLSv1.2", ...],
    "enabledProtocols": [...],
    "supportedCipherSuites": [...],
    "enabledCipherSuites": [...],
    "namedGroups": {
      "supported": [],
      "enabled": [],
      "note": "..."
    }
  },
  "serverCertificate": {
    "subject": "...",
    "issuer": "...",
    "notBefore": "...",
    "notAfter": "...",
    "publicKeyAlgorithm": "RSA",
    "publicKeySizeBits": 2048,
    "signatureAlgorithm": "SHA256withRSA",
    "san": ["DNS:localhost", "IP:127.0.0.1"]
  },
  "pqc": {
    "presentInDefaultProviders": false,
    "note": "Java 17 default providers do not include standardized PQC algorithms (e.g., ML-KEM/ML-DSA)."
  }
}
```

Implementation notes:
- TLS info: `SSLContext.getDefault()` + `SSLParameters` from supported/default
- Named groups: try `jdk.tls.namedGroups` system property; return empty arrays with note if unavailable
- Certificate: load from keystore via `KeystoreConfig` properties
- Key size: `((RSAPublicKey) key).getModulus().bitLength()` or `((ECPublicKey) key).getParams().getCurve().getField().getFieldSize()`

---

## scripts/client-demo.sh

Must show the crypto used when querying `https://localhost:8443/hello`:
- Negotiated protocol (expect: TLSv1.2)
- Negotiated cipher suite (e.g., ECDHE-RSA-AES128-GCM-SHA256)
- Server cert public key algorithm + size (RSA 2048)
- Server cert signature algorithm (sha256WithRSAEncryption)
- Successful GET /hello using `--cacert tls/server-cert.pem` (no `-k`)

Output format:
```
TLS Negotiation:
  Protocol: TLSv1.2
  Cipher: ECDHE-RSA-AES128-GCM-SHA256

Server Certificate:
  Public Key: RSA 2048
  Signature: sha256WithRSAEncryption

GET /hello:
  hello world
```

---

## README.md

Keep short:
- Prerequisites: Java 17, Maven 3.8+, OpenSSL, curl
- Certs are included under `./tls` (with regeneration instructions)
- Run: `mvn spring-boot:run`
- Demo: `./scripts/client-demo.sh`
- Branch structure table (main only for now; future branches for PQC migration)
- "Why this matters" section on quantum threat and migration path

---

## Acceptance Criteria
- `https://localhost:8443/hello` returns `hello world`
- HTTP is not exposed
- `https://localhost:8443/crypto/capabilities` returns full JSON with:
  - supported/enabled protocols (TLS 1.2 only)
  - cipher suites
  - certificate details with public key size
  - PQC status (false)
- `scripts/client-demo.sh`:
  - prints TLS 1.2 protocol + cipher suite
  - prints cert key size (RSA 2048) + signature algorithm
  - calls /hello with `--cacert` (no `-k`)
- Code uses enterprise legacy patterns throughout (verbose POJOs, interface+impl, field injection, no var/records/pattern matching)
- Migration blockers are present and documented:
  - `javax.servlet.Filter` in RequestLoggingFilter (namespace blocker)
  - Hardcoded `SSLContext.getInstance("TLSv1.2")` in SslConfig (PQC protocol blocker)
  - `Security.setProperty()` with classical-only algorithms in PqcDemoApplication (PQC config blocker)
  - Custom `X509TrustManager` with `instanceof` checks that don't handle PQC key types
- ~12 Java source files in layered package structure
