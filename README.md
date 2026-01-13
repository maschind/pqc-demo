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
| `main` | 17 | 1.2 | ⚠️ Unsafe | Baseline: typical enterprise Java app with classical crypto |
| `feature/pqc-ready` | 25 | 1.3 | 🟡 Transitional | PQC algorithms available, TLS hybrid pending (workaround using BC) ← **You are here** |
| `feature/pqc-safe` | 25 | 1.3 | ✅ PQC-Safe | **TODO:** All classical-only algorithms disabled |

### Branch Details

#### `main` - Unsafe Baseline
- Java 17 with TLS 1.2 only
- RSA-2048 server certificate
- ECDHE key exchange (secp256r1)
- Represents a typical enterprise Java 17 application
- **Vulnerable to "harvest now, decrypt later" quantum attacks**

#### `feature/pqc-ready` - Transitional
- Java 25 with TLS 1.3
- Hybrid key exchange (classical + ML-KEM) - workaround using BC as JEP527 is forseen for Java27
- ML-DSA capable signatures
- Backward compatible with classical clients - fallback attack possible
- **Safe against "harvest now, decrypt later" attacks**

#### `feature/pqc-ready` - **#TODO**

## Prerequisites

- **Java 25** (required for BouncyCastle compatibility)
- Maven 3.8+
- **OpenSSL 3.5+** (required for ML-KEM client negotiation)
- curl

## Quick Start

### 1. Start the PQC Server

```bash
./scripts/run-pqc-server.sh
```

Or directly:
```bash
mvn exec:java -Dexec.mainClass="com.example.pqcdemo.PqcHttpsServer"
```

The server starts on **https://localhost:8443** with ML-KEM hybrid TLS.

### 2. Test PQC Connection

```bash
./scripts/client-demo.sh
```

Expected output:
```
═══════════════════════════════════════════════════════════════
  PQC TLS Connection (ML-KEM Hybrid Key Exchange)
═══════════════════════════════════════════════════════════════

  Protocol:         TLSv1.3
  Cipher:           TLS_AES_256_GCM_SHA384
  Negotiated Group: X25519MLKEM768
  Key Exchange:     ★ ML-KEM HYBRID (Quantum-Safe!)
```

### 3. Test Classical Fallback (Crypto Agility)

```bash
./scripts/client-demo-unsafe.sh
```

This forces classical-only key exchange to demonstrate backward compatibility.

## How It Works

### BouncyCastle JSSE 1.81

[BouncyCastle 1.81](https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/) added ML-KEM hybrid TLS support:

| Component | Version | Purpose |
|-----------|---------|---------|
| `bcprov-jdk18on` | 1.81 | Core crypto + PQC algorithms |
| `bctls-jdk18on` | 1.81 | **TLS with ML-KEM hybrid key exchange** |
| `bcpkix-jdk18on` | 1.81 | PKI/X.509 support |

### Standalone Server (Not Quarkus)

The `PqcHttpsServer.java` uses Java's built-in `HttpsServer` with BCJSSE directly:

```java
// Register BouncyCastle providers
Security.insertProviderAt(new BouncyCastleProvider(), 1);
Security.insertProviderAt(new BouncyCastleJsseProvider(false), 2);

// Create SSLContext with BCJSSE
SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
```

> **Why not Quarkus?** Quarkus/Vert.x has hardcoded dependencies on SunJSSE and cannot use BCJSSE for TLS. The standalone server bypasses this limitation.

## API Endpoints

### GET /hello

```bash
curl -sk https://localhost:8443/hello
# Output: hello world (PQC-enabled via BCJSSE 1.81+)
```

### GET /crypto/info

```bash
curl -sk https://localhost:8443/crypto/info | python3 -m json.tool
```

Returns:
```json
{
  "server": "PqcHttpsServer",
  "java.version": "25.0.1",
  "tls": {
    "provider": "BCJSSE 1.81+",
    "protocol": "TLS 1.3",
    "keyExchange": {
      "algorithm": "X25519MLKEM768",
      "quantumSafe": true
    },
    "authentication": {
      "algorithm": "ECDSA-SHA384",
      "quantumSafe": false
    }
  },
  "pqc": {
    "keyExchangeSafe": true,
    "availableAlgorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
  }
}
```

## TLS Certificates

Three certificate options are available in `./tls`:

| File | Algorithm | Use Case |
|------|-----------|----------|
| `server-keystore-hybrid.p12` | ECDSA | Default - works with all clients |
| `server-keystore-mldsa.p12` | ML-DSA | Full PQC - needs PQC-capable client |
| `server-keystore.p12` | RSA-2048 | Legacy compatibility |

To regenerate:

```bash
# ECDSA certificate (recommended for hybrid PQC)
keytool -genkeypair -alias server -keyalg EC -groupname secp384r1 \
  -sigalg SHA384withECDSA -validity 3650 \
  -keystore tls/server-keystore-hybrid.p12 -storetype PKCS12 \
  -storepass changeit -dname "CN=localhost, OU=Dev, O=Demo, L=Zurich, ST=ZH, C=CH" \
  -ext "SAN=DNS:localhost,IP:127.0.0.1"

# Export for curl
keytool -exportcert -alias server -keystore tls/server-keystore-hybrid.p12 \
  -storepass changeit -rfc -file tls/server-cert-hybrid.pem

# ML-DSA certificate (full PQC - for future use)
keytool -genkeypair -alias server -keyalg ML-DSA-65 -validity 3650 \
  -keystore tls/server-keystore-mldsa.p12 -storetype PKCS12 \
  -storepass changeit -dname "CN=localhost, OU=Dev, O=Demo, L=Zurich, ST=ZH, C=CH" \
  -ext "SAN=DNS:localhost,IP:127.0.0.1"
```

## Crypto Agility

The server supports **both PQC and classical clients**:

| Client Capability | Negotiated Key Exchange |
|-------------------|------------------------|
| OpenSSL 3.5+ with ML-KEM | X25519MLKEM768 (quantum-safe) |
| Classical clients | X25519 or P-256 (fallback) |

This is demonstrated by:
- `./scripts/client-demo.sh` - Uses ML-KEM hybrid
- `./scripts/client-demo-unsafe.sh` - Forces classical only

## Why This Matters

### "Harvest Now, Decrypt Later"

Adversaries can:
1. Capture encrypted traffic today
2. Store it until quantum computers are available
3. Decrypt everything retroactively

**ML-KEM hybrid key exchange protects against this threat.**

### Current Protection Status

| Layer | This Branch | Protection |
|-------|-------------|------------|
| Key Exchange | ML-KEM hybrid | ✅ Quantum-safe |
| Authentication | ECDSA | ⚠️ Classical (ML-DSA ready) |
| Symmetric Cipher | AES-256-GCM | ✅ Quantum-safe |

## Migration Path

```
main (vulnerable)  →  feature/pqc-ready (hybrid)  →  feature/pqc-safe (full PQC)
      ↓                        ↓                            ↓
   TLS 1.2                 TLS 1.3                      TLS 1.3
   Java 17                 Java 25                      Java 25
   ECDHE only              ML-KEM + ECDHE               ML-KEM only
   RSA cert                ECDSA cert                   ML-DSA cert
```

## References

- [BouncyCastle 1.81 Release](https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/) - ML-KEM hybrid TLS support
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [JEP 527: Hybrid Key Exchange for TLS](https://bugs.openjdk.org/browse/JDK-8369848) - Future native JSSE support
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final) - NIST standard for key encapsulation
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) - NIST standard for digital signatures
