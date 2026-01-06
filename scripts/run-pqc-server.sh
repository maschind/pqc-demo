#!/bin/bash
# Run standalone PQC HTTPS server with ML-KEM hybrid TLS
# Uses Java 25 HttpsServer with BouncyCastle JSSE 1.81+
#
# BouncyCastle 1.81 added ML-KEM hybrid TLS support:
# https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/

set -e
cd "$(dirname "$0")/.."

echo "Building project..."
mvn compile -q

echo "Starting PQC HTTPS Server on port 8443..."
echo ""
mvn exec:java -Dexec.mainClass="com.example.pqcdemo.PqcHttpsServer" -q

# Test with:
#   openssl s_client -connect localhost:8443 -servername localhost
# Should show: Negotiated TLS1.3 group: X25519MLKEM768

