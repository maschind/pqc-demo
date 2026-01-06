#!/bin/bash
# TLS Crypto Demo - Shows negotiated TLS details when connecting to HTTPS server
# Demonstrates: protocol, cipher suite, certificate key size, signature algorithm

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/util.sh"

SERVER_HOST="${SERVER_HOST:-localhost}"
SERVER_PORT="${SERVER_PORT:-8080}"
CERT_FILE="$PROJECT_DIR/tls/server-cert.pem"

print_header "Java 17 HTTPS Crypto Demo - TLS Connection Analysis"

# Verify certificate file exists
if [ ! -f "$CERT_FILE" ]; then
    print_error "Certificate file not found: $CERT_FILE"
    print_info "Generate it with: keytool -exportcert -alias server -keystore tls/server-keystore.p12 -storepass changeit -rfc -file tls/server-cert.pem"
    exit 1
fi

# Check if server is running
echo "Checking server availability at https://$SERVER_HOST:$SERVER_PORT ..."
if ! openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" </dev/null 2>/dev/null | grep -q "CONNECTED"; then
    print_error "Server not available at $SERVER_HOST:$SERVER_PORT"
    print_info "Start the server with: mvn quarkus:dev"
    exit 1
fi
print_success "Server is running"

# Get TLS negotiation details
print_header "TLS Negotiation"

TLS_OUTPUT=$(echo | openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" 2>/dev/null)

# Extract protocol
PROTOCOL=$(echo "$TLS_OUTPUT" | grep -E "Protocol\s*:" | head -1 | sed 's/.*Protocol *: *//')
if [ -z "$PROTOCOL" ]; then
    # Try alternate format for different openssl versions
    PROTOCOL=$(echo "$TLS_OUTPUT" | grep -E "^\s+Protocol\s*:" | head -1 | sed 's/.*: *//')
fi

# Extract cipher suite
CIPHER=$(echo "$TLS_OUTPUT" | grep -E "Cipher\s*:" | head -1 | sed 's/.*Cipher *: *//')
if [ -z "$CIPHER" ]; then
    CIPHER=$(echo "$TLS_OUTPUT" | grep -E "^\s+Cipher\s*:" | head -1 | sed 's/.*: *//')
fi

echo "  Protocol: ${PROTOCOL:-unknown}"
echo "  Cipher:   ${CIPHER:-unknown}"

# Get server certificate details
print_header "Server Certificate"

CERT_OUTPUT=$(echo | openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)

# Extract public key info
PUB_KEY_LINE=$(echo "$CERT_OUTPUT" | grep -A1 "Public Key Algorithm:" | head -2)
KEY_ALGO=$(echo "$PUB_KEY_LINE" | grep "Public Key Algorithm:" | sed 's/.*: //')
KEY_SIZE=$(echo "$CERT_OUTPUT" | grep -E "(RSA Public-Key:|Public-Key:)" | grep -oE '\([0-9]+ bit\)' | tr -d '()')

# Extract signature algorithm
SIG_ALGO=$(echo "$CERT_OUTPUT" | grep "Signature Algorithm:" | head -1 | sed 's/.*: //')

echo "  Public Key: ${KEY_ALGO:-unknown} ${KEY_SIZE:-unknown}"
echo "  Signature:  ${SIG_ALGO:-unknown}"

# Call the endpoint
print_header "GET /hello"

RESPONSE=$(curl --silent --cacert "$CERT_FILE" "https://$SERVER_HOST:$SERVER_PORT/hello")
echo "  $RESPONSE"

# Summary
print_header "Summary"
echo "This connection used classical (non-PQC) TLS:"
echo ""
echo "  TLS Protocol:    ${PROTOCOL:-unknown}"
echo "  Cipher Suite:    ${CIPHER:-unknown}"
echo "  Key Exchange:    (part of cipher suite - typically ECDHE)"
echo "  Server Key:      ${KEY_ALGO:-unknown} ${KEY_SIZE:-unknown}"
echo "  Signature:       ${SIG_ALGO:-unknown}"
echo ""
print_info "Note: Java 17 default TLS uses classical algorithms only."
print_info "PQC migration requires Java 21+ or third-party providers."
