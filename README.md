# Post-Quantum Cryptography Migration Demo

> **WARNING: NOT FOR PRODUCTION USE**
>
> This repository is intentionally insecure and meant for educational/demo purposes only.
> The `main` branch uses outdated cryptographic configurations vulnerable to quantum attacks.
> See [SECURITY.md](SECURITY.md) for details.

A hands-on demonstration of migrating a Java enterprise application from classical cryptography to post-quantum cryptography (PQC). Start with a typical enterprise Java 17 Spring Boot app, then follow the migration path to Java 25 with PQC support.

## Branch Structure

| Branch | Java | Framework | TLS | Security Posture | Description |
|--------|------|-----------|-----|------------------|-------------|
| `main` | 17 | Spring Boot 2.7 | 1.2 | Unsafe | Baseline: typical enterprise Java app with classical crypto |
| *(planned)* | 25 | Spring Boot 3.x | 1.3 | Transitional | Upgraded runtime with hybrid PQC support |
| *(planned)* | 25 | Spring Boot 3.x | 1.3 | PQC-Safe | All classical-only algorithms disabled |

### `main` — Unsafe Baseline (Current)
- Java 17 with TLS 1.2 only
- Spring Boot 2.7.18 (javax.* namespace)
- RSA-2048 server certificate
- ECDHE key exchange (secp256r1)
- Enterprise legacy code patterns (verbose POJOs, interface+impl services, field injection)
- Hardcoded TLS 1.2 SSLContext, classical-only named groups, javax.servlet filters
- **Vulnerable to "harvest now, decrypt later" quantum attacks**

## Migration Challenges

This codebase contains **4 categories of real enterprise migration friction** — each demonstrated in specific files:

### 1. Namespace Migration: javax.* → jakarta.*
**File:** [`filter/RequestLoggingFilter.java`](src/main/java/com/example/pqcdemo/filter/RequestLoggingFilter.java)

Spring Boot 2.7 uses `javax.servlet.*`. Spring Boot 3.x requires `jakarta.servlet.*`. This isn't just a search-and-replace in your code — every JAR on the classpath that touches the Servlet API must also be Jakarta-compatible. A single incompatible dependency causes `ClassNotFoundException` at runtime. Enterprise apps with 50-200 transitive dependencies must audit all of them.

**PQC impact:** You can't upgrade to Spring Boot 3 (with better TLS 1.3/PQC defaults) until this is resolved. The namespace is the gate.

### 2. Hardcoded TLS 1.2 SSLContext
**File:** [`config/SslConfig.java`](src/main/java/com/example/pqcdemo/config/SslConfig.java)

`SSLContext.getInstance("TLSv1.2")` locks outbound connections to TLS 1.2. A custom `X509TrustManager` logs certificate chains using `instanceof RSAPublicKey` / `ECPublicKey` checks — it won't recognize PQC key types (ML-DSA). Enterprise security teams mandate these configurations, and changing them requires security review + change management approval.

**PQC impact:** Direct blocker — PQC key exchange (ML-KEM) requires TLS 1.3. Hardcoded TLS 1.2 prevents it entirely.

### 3. Security Property Lock-in
**File:** [`PqcDemoApplication.java`](src/main/java/com/example/pqcdemo/PqcDemoApplication.java)

`Security.setProperty("jdk.tls.namedGroups", ...)` explicitly lists classical ECDHE curves. PQC hybrid groups (e.g., `x25519_ml-kem-768`) must be added or they won't be negotiated. These properties are often deployed via `java.security` policy files across hundreds of servers.

**PQC impact:** Direct blocker — even on Java 25 with PQC support, the named groups list must be updated before PQC key exchange can occur.

### 4. Language-Level Verbosity
**Files:** All `model/*.java`, `service/*Impl.java`, controllers

Verbose POJOs (40+ lines each → 1-line Records), `instanceof` + cast chains, `new ArrayList<>()` loops, interface+impl services. Not technically hard to modernize, but enterprise codebases have thousands of these patterns. Automated tools (OpenRewrite) help, but each change needs validation and review.

### Migration Dependency Chain

```
Language modernization (Records, pattern matching, var)
  └→ Namespace migration (javax → jakarta)
       └→ Framework upgrade (Spring Boot 2.7 → 3.x)
            └→ TLS configuration update (TLS 1.2 → 1.3)
                 └→ Security policy update (add PQC named groups)
                      └→ PQC key exchange and certificates (ML-KEM, ML-DSA)
```

Each step has its own stakeholders, review process, and risk profile. This is why PQC migration in enterprise takes months, not days.

## Prerequisites

- Java 17
- Maven 3.8+
- OpenSSL
- curl

## TLS Certificates

Self-signed certificates are included in `./tls`:
- `server-keystore.p12` — PKCS12 keystore with RSA-2048 certificate
- `server-cert.pem` — Exported PEM certificate for curl

To regenerate (optional):

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

## Run the Application

```bash
mvn spring-boot:run
```

The server starts on **HTTPS only** at `https://localhost:8443`.

## Run the Client Demo

In a separate terminal:

```bash
./scripts/client-demo.sh
```

This shows:
- Negotiated TLS protocol (TLSv1.2)
- Negotiated cipher suite (e.g., ECDHE-RSA-AES128-GCM-SHA256)
- Server certificate key algorithm + size (RSA 2048)
- Server certificate signature algorithm

## API Endpoints

### GET /hello

```bash
curl --cacert tls/server-cert.pem https://localhost:8443/hello
```

### GET /crypto/capabilities

```bash
curl --cacert tls/server-cert.pem https://localhost:8443/crypto/capabilities | python3 -m json.tool
```

Returns: Java runtime info, security providers, TLS protocols/cipher suites, server certificate details, and PQC availability status.

## Why This Matters

### The Quantum Threat

| Algorithm | Type | Quantum Vulnerable? | Replacement |
|-----------|------|---------------------|-------------|
| RSA-2048 | Signatures, Key Exchange | Yes (Shor's algorithm) | ML-DSA, ML-KEM |
| ECDHE | Key Exchange | Yes (Shor's algorithm) | ML-KEM |
| ECDSA | Signatures | Yes (Shor's algorithm) | ML-DSA |
| AES-256 | Symmetric | Weakened (Grover's) | AES-256 (still safe) |
| SHA-256 | Hash | Weakened (Grover's) | SHA-256 (still safe) |

### "Harvest Now, Decrypt Later"

Adversaries can capture encrypted traffic today, store it, and decrypt everything retroactively once quantum computers are available. **Long-lived secrets and sensitive data are at risk NOW.**

## Migration Path

```
main (unsafe)  →  pqc-ready (hybrid)  →  pqc-safe (PQC-only)
     ↓                   ↓                      ↓
  TLS 1.2            TLS 1.3                TLS 1.3
  Java 17            Java 25                Java 25
  Spring Boot 2.7    Spring Boot 3.x        Spring Boot 3.x
  javax.*            jakarta.*              jakarta.*
  RSA/ECDHE          Hybrid ML-KEM          ML-KEM only
  Classical          Classical + PQC        PQC only
  Legacy patterns    Modern Java            Modern Java
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
- [Spring Boot](https://spring.io/projects/spring-boot)
