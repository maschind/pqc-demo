# Security Policy

## ⚠️ WARNING: NOT FOR PRODUCTION USE

**This repository is intentionally insecure and exists solely for educational and demonstration purposes.**

### What This Repo Demonstrates

This is a Post-Quantum Cryptography (PQC) migration demo that shows the evolution from vulnerable classical cryptography to quantum-safe algorithms across different branches.

### Known Vulnerabilities (By Design)

#### `main` Branch
- **TLS 1.2 only** — Lacks TLS 1.3 security improvements
- **RSA-2048** — Vulnerable to Shor's algorithm on quantum computers
- **ECDHE (secp256r1)** — Vulnerable to Shor's algorithm on quantum computers
- **Self-signed certificates** — No certificate chain validation
- **Hardcoded passwords** — Keystore uses `changeit`

#### All Branches
- Self-signed certificates (not trusted by default)
- Demo-quality code (not hardened for production)
- No input validation beyond framework defaults
- No rate limiting or security headers

### Do NOT Use This Code For

- Production systems
- Handling real user data
- Protecting sensitive information
- Any security-critical application

### Intended Use

- Learning about PQC migration
- Demonstrating crypto capabilities
- Workshops and presentations
- Understanding the difference between classical and post-quantum cryptography

### Reporting Security Issues

This repository is intentionally vulnerable. Please do not report the known vulnerabilities listed above.

If you find a vulnerability that could affect people who clone this repo for educational purposes (e.g., malicious code injection), please open an issue.

## License

This demo is provided as-is with no warranty. Use at your own risk.

