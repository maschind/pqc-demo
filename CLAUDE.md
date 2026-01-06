# CLAUDE.md — Java 25 Quarkus HTTPS Crypto Demo (PQC-Ready)

## Goal (5-minute demo)
Build a minimal Java 25 HTTPS server that demonstrates **working ML-KEM hybrid TLS**:
- serves **HTTPS** only using **BouncyCastle JSSE 1.81**
- exposes:
  - `GET https://localhost:8443/hello`
  - `GET https://localhost:8443/crypto/info`
- uses **TLS 1.3** with **ML-KEM hybrid key exchange** (X25519MLKEM768)
- demonstrates **crypto agility** (supports both PQC and classical clients)
- includes scripts to show PQC vs classical TLS negotiation

This demo shows: "Java 25 PQC-ready infrastructure with ML-KEM/ML-DSA algorithms available."

---

## Implementation Notes

### Why Standalone Server (Not Quarkus)?
Quarkus/Vert.x has hardcoded dependencies on SunJSSE and cannot use BCJSSE for TLS.
The standalone `PqcHttpsServer.java` uses Java's built-in `HttpsServer` with BCJSSE directly,
enabling ML-KEM hybrid key exchange.

### BouncyCastle 1.81 Requirement
[BouncyCastle 1.81](https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/)
added ML-KEM hybrid TLS support. Earlier versions (1.79, 1.80) do NOT support ML-KEM in TLS.

---

## Constraints
- Java: 25 (required for BouncyCastle compatibility)
- TLS Provider: BouncyCastle JSSE 1.81+
- TLS: self-signed certificate, local only, TLS 1.3
- Key Exchange: ML-KEM hybrid (X25519MLKEM768) with classical fallback
- Prefer clarity over features: minimal source code

---

## Deliverables
1) Standalone HTTPS server with BCJSSE (`PqcHttpsServer.java`)
2) Endpoint: `GET /hello` -> `hello world (PQC-enabled via BCJSSE 1.81+)`
3) Endpoint: `GET /crypto/info` -> JSON showing TLS/PQC status
4) Script `scripts/run-pqc-server.sh` to start the server
5) Script `scripts/client-demo.sh` that:
   - calls `https://localhost:8443/hello`
   - shows ML-KEM hybrid key exchange (X25519MLKEM768)
   - confirms quantum-safe key establishment
6) Script `scripts/client-demo-unsafe.sh` that:
   - forces classical-only key exchange
   - demonstrates crypto agility / backward compatibility

---

## Repository Layout
```
.
├─ CLAUDE.md
├─ README.md
├─ pom.xml
├─ src/main/java/.../
│  ├─ PqcHttpsServer.java        (standalone HTTPS server with BCJSSE)
│  ├─ HelloResource.java         (Quarkus - not used for PQC)
│  ├─ CryptoCapabilitiesResource.java  (Quarkus - not used for PQC)
│  └─ BouncyCastleInitializer.java     (Quarkus BC setup)
├─ scripts/
│  ├─ run-pqc-server.sh          (start PQC server)
│  ├─ client-demo.sh             (PQC connection demo)
│  ├─ client-demo-unsafe.sh      (classical fallback demo)
│  └─ util.sh
└─ tls/
   ├─ server-keystore-hybrid.p12  (ECDSA - default, works with all clients)
   ├─ server-keystore-mldsa.p12   (ML-DSA - full PQC, future use)
   ├─ server-cert-hybrid.pem      (exported PEM for curl)
   └─ server-keystore.p12         (RSA - legacy)
```

---

## TLS Certificates

### Certificate Options
| File | Algorithm | Quantum-Safe | Client Compatibility |
|------|-----------|--------------|---------------------|
| `server-keystore-hybrid.p12` | ECDSA | Auth: No, KEX: Yes | ✅ All clients |
| `server-keystore-mldsa.p12` | ML-DSA | Auth: Yes, KEX: Yes | ❌ PQC clients only |

### Generate ECDSA Certificate (Default)
```bash
keytool -genkeypair -alias server -keyalg EC -groupname secp384r1 \
  -sigalg SHA384withECDSA -validity 3650 \
  -keystore tls/server-keystore-hybrid.p12 -storetype PKCS12 \
  -storepass changeit -dname "CN=localhost, OU=Dev, O=Demo, L=Zurich, ST=ZH, C=CH" \
  -ext "SAN=DNS:localhost,IP:127.0.0.1"

keytool -exportcert -alias server -keystore tls/server-keystore-hybrid.p12 \
  -storepass changeit -rfc -file tls/server-cert-hybrid.pem
```

### Generate ML-DSA Certificate (Full PQC)
```bash
keytool -genkeypair -alias server -keyalg ML-DSA-65 -validity 3650 \
  -keystore tls/server-keystore-mldsa.p12 -storetype PKCS12 \
  -storepass changeit -dname "CN=localhost, OU=Dev, O=Demo, L=Zurich, ST=ZH, C=CH" \
  -ext "SAN=DNS:localhost,IP:127.0.0.1"
```

---

## PqcHttpsServer Implementation

Key points:
1. Register BouncyCastle providers FIRST
2. Create SSLContext with BCJSSE explicitly
3. Use Java's HttpsServer (not Netty/Vert.x)

```java
// Register BC providers
Security.insertProviderAt(new BouncyCastleProvider(), 1);
Security.insertProviderAt(new BouncyCastleJsseProvider(false), 2);

// Create SSLContext with BCJSSE
SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

// Create HTTPS server
HttpsServer server = HttpsServer.create(new InetSocketAddress(8443), 0);
server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
```

---

## REST API Spec

### GET /hello
- Response: `hello world (PQC-enabled via BCJSSE 1.81+)`
- URL: `https://localhost:8443/hello`

### GET /crypto/info
Response:
```json
{
  "server": "PqcHttpsServer",
  "java.version": "25.0.1",
  "tls": {
    "provider": "BCJSSE 1.81+",
    "protocol": "TLS 1.3",
    "keyExchange": {
      "algorithm": "X25519MLKEM768",
      "quantumSafe": true,
      "type": "ML-KEM hybrid (X25519 + ML-KEM-768)"
    },
    "authentication": {
      "algorithm": "ECDSA-SHA384",
      "quantumSafe": false,
      "note": "ML-DSA available but requires PQC-capable clients"
    },
    "cipher": "AES-256-GCM"
  },
  "pqc": {
    "keyExchangeSafe": true,
    "authenticationSafe": false,
    "availableAlgorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
  }
}
```

---

## scripts/client-demo.sh Output

```
═══════════════════════════════════════════════════════════════
  PQC TLS Connection (ML-KEM Hybrid Key Exchange)
═══════════════════════════════════════════════════════════════

=== TLS Negotiation ===

  Protocol:         TLSv1.3
  Cipher:           TLS_AES_256_GCM_SHA384
  Negotiated Group: X25519MLKEM768
  Key Exchange:     ★ ML-KEM HYBRID (Quantum-Safe!)

=== Server Certificate ===

  Public Key:       id-ecPublicKey 384 bit
  Signature:        ecdsa-with-SHA384

=== GET /hello ===

  hello world (PQC-enabled via BCJSSE 1.81+)

═══════════════════════════════════════════════════════════════
  Summary: PQC-Safe TLS Connection
═══════════════════════════════════════════════════════════════

  ✓ Key Exchange: ML-KEM hybrid (X25519 + ML-KEM-768)
    → Quantum-safe key establishment
    → Protected against 'harvest now, decrypt later' attacks
```

---

## scripts/client-demo-unsafe.sh Output

```
═══════════════════════════════════════════════════════════════
  Classical TLS Connection (NO Quantum Protection)
═══════════════════════════════════════════════════════════════

⚠️  Forcing classical-only key exchange: X25519:P-256:P-384

=== TLS Negotiation ===

  Protocol:         TLSv1.3
  Cipher:           TLS_AES_256_GCM_SHA384
  Negotiated Group: X25519, 253 bits
  Key Exchange:     ✗ X25519, 253 bits (NOT quantum-safe!)

═══════════════════════════════════════════════════════════════
  Summary: Classical TLS Connection (NOT Quantum-Safe)
═══════════════════════════════════════════════════════════════

  ✗ Key Exchange: Classical X25519, 253 bits
    → NOT quantum-safe
    → Vulnerable to 'harvest now, decrypt later' attacks
```

---

## Acceptance Criteria
- [x] `https://localhost:8443/hello` returns "hello world"
- [x] Server uses BCJSSE for TLS (not SunJSSE)
- [x] ML-KEM hybrid key exchange negotiated (X25519MLKEM768)
- [x] `scripts/client-demo.sh` shows PQC key exchange
- [x] `scripts/client-demo-unsafe.sh` shows classical fallback
- [x] Crypto agility: server accepts both PQC and classical clients
- [x] ECDSA certificate works with all clients
- [x] ML-DSA certificate available for full PQC (future)
