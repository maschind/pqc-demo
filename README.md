# Post-Quantum Cryptography Migration Demo

> ⚠️ **WARNING: NOT FOR PRODUCTION USE**
>
> This repository is intentionally insecure and meant for educational/demo purposes only.
> The `main` branch uses outdated cryptographic configurations vulnerable to quantum attacks.
> See [SECURITY.md](SECURITY.md) for details.

A hands-on demonstration of migrating a Java enterprise application from classical cryptography to post-quantum cryptography (PQC). This repo shows the evolution across three branches representing different security postures.

## Branch Structure

| Branch | Java | TLS | Security Posture | Description |
|--------|------|-----|------------------|-------------|
| `main` | 17 | 1.2 | ⚠️ Unsafe | Baseline: typical enterprise Java app with classical crypto |
| `feature/pqc-ready` | 25 | 1.3 | 🟡 Transitional | Upgraded runtime with hybrid PQC support |
| `feature/pqc-safe` | 25 | 1.3 | ✅ PQC-Safe | **TODO:** All classical-only algorithms disabled |

### Branch Details

#### `main` — Unsafe Baseline (Current)
- Java 17 with TLS 1.2 only
- RSA-2048 server certificate
- ECDHE key exchange (secp256r1)
- Represents a typical enterprise Java 17 application
- **Vulnerable to "harvest now, decrypt later" quantum attacks**

#### `feature/pqc-ready` — Transitional
- Java 25 with TLS 1.3
- Hybrid key exchange (classical + ML-KEM)
- ML-DSA capable signatures
- Backward compatible with classical clients
- **Safe against future quantum computers**

#### `feature/pqc-safe` — Fully PQC
- Java 25 with TLS 1.3
- ML-KEM only key exchange (no classical fallback)
- ML-DSA only signatures
- All vulnerable classical algorithms disabled
- **Maximum quantum security, no backward compatibility**

## Prerequisites

- Java 17 (this branch)
- Maven 3.8+
- OpenSSL
- curl

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
- Java runtime info
- Security providers
- TLS protocols and cipher suites (supported + enabled)
- Server certificate details (algorithm, key size, signature)
- PQC availability status

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
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
- [Quarkus](https://quarkus.io/)
