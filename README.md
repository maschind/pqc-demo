# Post-Quantum Cryptography Migration Demo

> ⚠️ **WARNING: NOT FOR PRODUCTION USE**
>
> This repository is intentionally insecure and meant for educational/demo purposes only.
> The `main` branch uses outdated cryptographic configurations vulnerable to quantum attacks.
> See [SECURITY.md](SECURITY.md) for details.
> This branch (`feature/pqc-ready`) uses Java 25 with ML-KEM/ML-DSA algorithms available.
> TLS 1.3 with strong cipher suites. PQC algorithms present but TLS hybrid key exchange
> awaits future JSSE integration. See [SECURITY.md](SECURITY.md) for details.

A hands-on demonstration of migrating a Java enterprise application from classical cryptography to post-quantum cryptography (PQC). This repo shows the evolution across three branches representing different security postures.

## Branch Structure

| Branch | Java | TLS | Security Posture | Description |
|--------|------|-----|------------------|-------------|
| `main` | 17 | 1.2 | ⚠️ **Unsafe** | Baseline: typical enterprise Java app with classical crypto |
| `feature/pqc-ready` | 25 | 1.3 | 🟡 Transitional | PQC algorithms available, TLS hybrid pending ← **You are here** |
| `feature/pqc-safe` | 25 | 1.3 | ✅ **PQC-Safe** | All classical-only algorithms disabled |

### Branch Details

#### `main` — Unsafe Baseline
- Java 17 with TLS 1.2 only
- RSA-2048 server certificate
- ECDHE key exchange (secp256r1)
- Represents a typical enterprise Java 17 application
- **Vulnerable to "harvest now, decrypt later" quantum attacks**

#### `feature/pqc-ready` — Transitional
- Java 25 with TLS 1.3
- ML-KEM and ML-DSA algorithms available as primitives
- ECDHE key exchange (TLS hybrid awaits JSSE integration)
- Infrastructure ready for PQC when TLS support is added
- **Prepares for quantum-safe future**

> 📌 **JEP 527 Status:** [JEP 527: Hybrid Key Exchange for TLS](https://bugs.openjdk.org/browse/JDK-8369848)
> is not yet available in Java 25. This branch includes **BouncyCastle** to provide PQC algorithms
> (Kyber, Dilithium) for application-level crypto. Full TLS hybrid key exchange awaits JEP 527
> or custom SSLContext configuration.

#### `feature/pqc-safe` — Fully PQC
- Java 25 with TLS 1.3
- ML-KEM only key exchange (no classical fallback)
- ML-DSA only signatures
- All vulnerable classical algorithms disabled
- **Maximum quantum security, no backward compatibility**

## Prerequisites

- **Java 25** (required for native ML-KEM/ML-DSA support)
- Maven 3.8+
- **OpenSSL 3.5+** (recommended for ML-KEM client negotiation)
- curl

## BouncyCastle PQC Workaround

Since JEP 527 is not yet available, this branch uses **BouncyCastle** to provide actual PQC-safe TLS:

| Component | Version | Purpose |
|-----------|---------|---------|
| `bcprov-jdk18on` | 1.79 | Core crypto + PQC algorithms (Kyber, Dilithium) |
| `bctls-jdk18on` | 1.79 | TLS provider with hybrid key exchange |
| `bcpkix-jdk18on` | 1.79 | PKI/X.509 support |

The `BouncyCastleInitializer` class registers these providers at startup, enabling:
- **PQC algorithms** (Kyber/ML-KEM, Dilithium/ML-DSA) for application-level crypto
- Security providers available at positions 1-2 in the JVM

> ⚠️ **Limitation:** Quarkus/Vert.x uses its own SSL engine (Netty) which doesn't automatically
> use BCJSSE for TLS connections. The BouncyCastle providers are available for **application-level**
> PQC operations (key encapsulation, signatures), but TLS hybrid key exchange requires either:
> - Waiting for [JEP 527](https://bugs.openjdk.org/browse/JDK-8369848) (native JSSE support)
> - Custom SSLContext configuration for Vert.x (complex)
> - A different server framework that uses BCJSSE directly

## TLS Certificates

Self-signed certificates are included in `./tls`:
- `server-keystore.p12` - PKCS12 keystore with RSA-2048 certificate
- `server-cert.pem` - Exported PEM certificate for curl

To regenerate (optional):

```bash
# Generate keystore
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

# Export certificate for curl
keytool -exportcert \
  -alias server \
  -keystore tls/server-keystore.p12 \
  -storepass changeit \
  -rfc \
  -file tls/server-cert.pem
```

## Run the Application

```bash
mvn quarkus:dev
```

The server starts on **HTTPS only** at `https://localhost:8080`.

## Run the Client Demo

In a separate terminal:

### PQC-Safe Connection (Recommended)
```bash
./scripts/client-demo.sh
```

This shows:
- Negotiated TLS protocol (TLSv1.3)
- Negotiated cipher suite with **hybrid ML-KEM key exchange**
- Server certificate key algorithm + size (RSA 2048)
- Quantum-safe session confirmation

### Classical Fallback (Backward Compatibility)
```bash
./scripts/client-demo-unsafe.sh
```

This forces classical-only key exchange to demonstrate backward compatibility with non-PQC clients.

## API Endpoints

### GET /hello

Basic endpoint returning "hello world".

```bash
curl --cacert tls/server-cert.pem https://localhost:8080/hello
```

### GET /crypto/capabilities

Returns JSON with runtime crypto capabilities:

```bash
curl --cacert tls/server-cert.pem https://localhost:8080/crypto/capabilities | python3 -m json.tool
```

Response includes:
- Java 25 runtime info
- Security providers with PQC algorithms
- TLS protocols and cipher suites (supported + enabled)
- **Named groups including ML-KEM hybrids**
- Server certificate details (algorithm, key size, signature)
- **PQC availability status (true)**

## Why This Matters

### The Quantum Threat

| Algorithm | Type | Quantum Vulnerable? | Replacement |
|-----------|------|---------------------|-------------|
| RSA-2048 | Signatures, Key Exchange | ✅ Yes (Shor's algorithm) | ML-DSA, ML-KEM |
| ECDHE | Key Exchange | ✅ Yes (Shor's algorithm) | ML-KEM |
| ECDSA | Signatures | ✅ Yes (Shor's algorithm) | ML-DSA |
| AES-256 | Symmetric | 🟡 Weakened (Grover's) | AES-256 (still safe) |
| SHA-256 | Hash | 🟡 Weakened (Grover's) | SHA-256 (still safe) |

### "Harvest Now, Decrypt Later"

Adversaries can:
1. Capture encrypted traffic today
2. Store it until quantum computers are available
3. Decrypt everything retroactively

**Long-lived secrets and sensitive data are at risk NOW.**

## Migration Path

```
main (unsafe)  →  feature/pqc-ready (hybrid)  →  feature/pqc-safe (PQC-only)
     ↓                      ↓                            ↓
  TLS 1.2              TLS 1.3                      TLS 1.3
  Java 17              Java 25                      Java 25
  RSA/ECDHE            Hybrid ML-KEM                ML-KEM only
  Classical            Classical + PQC              PQC only
```

## What to Observe

Run the demo on each branch and compare:

| Metric | `main` | `feature/pqc-ready` | `feature/pqc-safe` |
|--------|--------|---------------------|---------------------|
| TLS Protocol | 1.2 | 1.3 | 1.3 |
| Key Exchange | ECDHE | Hybrid (ECDHE + ML-KEM) | ML-KEM |
| Server Key | RSA-2048 | RSA-2048 or ML-DSA | ML-DSA |
| `pqc.presentInDefaultProviders` | false | true | true |

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [JEP 527: Hybrid Key Exchange for TLS](https://bugs.openjdk.org/browse/JDK-8369848) — ML-KEM integration into JSSE (future)
- [BouncyCastle](https://www.bouncycastle.org/) — PQC provider used as JEP 527 workaround
- [BouncyCastle PQC Documentation](https://www.bouncycastle.org/docs/tlsdocs1.8on/index.html)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
- [Quarkus](https://quarkus.io/)
