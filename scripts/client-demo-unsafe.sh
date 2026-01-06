#!/bin/bash
# Classical TLS Demo - Forces classical-only key exchange (no PQC)
# Demonstrates: Backward compatibility - server fallback to non-PQC key exchange

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/util.sh"

SERVER_HOST="${SERVER_HOST:-localhost}"
SERVER_PORT="${SERVER_PORT:-8443}"
CERT_FILE="$PROJECT_DIR/tls/server-cert-hybrid.pem"

# Force classical-only groups (NO ML-KEM hybrids)
CLASSICAL_GROUPS="X25519:P-256:P-384"

echo ""
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Classical TLS Connection (NO Quantum Protection)${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}⚠️  Forcing classical-only key exchange: ${CLASSICAL_GROUPS}${NC}"
echo ""

# Verify certificate file exists
if [ ! -f "$CERT_FILE" ]; then
    print_error "Certificate file not found: $CERT_FILE"
    print_info "Start the PQC server first: ./scripts/run-pqc-server.sh"
    exit 1
fi

# Check if server is running
echo "Checking server availability at https://$SERVER_HOST:$SERVER_PORT ..."
if ! openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" </dev/null 2>/dev/null | grep -q "CONNECTED"; then
    print_error "Server not available at $SERVER_HOST:$SERVER_PORT"
    print_info "Start the PQC server with: ./scripts/run-pqc-server.sh"
    exit 1
fi
print_success "Server is running"

# Get TLS negotiation details - FORCE CLASSICAL GROUPS
print_header "TLS Negotiation"

TLS_OUTPUT=$(echo | openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" -groups "$CLASSICAL_GROUPS" 2>&1)

# Extract protocol
PROTOCOL=$(echo "$TLS_OUTPUT" | grep -E "^Protocol:" | head -1 | sed 's/Protocol: *//')
if [ -z "$PROTOCOL" ]; then
    PROTOCOL=$(echo "$TLS_OUTPUT" | grep -E "Protocol\s*:" | head -1 | sed 's/.*Protocol *: *//')
fi

# Extract cipher suite
CIPHER=$(echo "$TLS_OUTPUT" | grep -E "Cipher is" | head -1 | sed 's/.*Cipher is //')
if [ -z "$CIPHER" ]; then
    CIPHER=$(echo "$TLS_OUTPUT" | grep -E "Cipher\s*:" | head -1 | sed 's/.*Cipher *: *//')
fi

# Extract negotiated group (should NOT be ML-KEM due to forced classical groups)
NEGOTIATED_GROUP=$(echo "$TLS_OUTPUT" | grep -E "Negotiated TLS1.3 group:" | head -1 | sed 's/.*group: *//')

# Extract key exchange / temp key (used for classical connections)
KEY_EXCHANGE=$(echo "$TLS_OUTPUT" | grep -E "Peer Temp Key:" | head -1 | sed 's/.*Peer Temp Key: *//')
if [ -z "$KEY_EXCHANGE" ]; then
    KEY_EXCHANGE=$(echo "$TLS_OUTPUT" | grep -E "Server Temp Key:" | head -1 | sed 's/.*Server Temp Key: *//')
fi

# Use KEY_EXCHANGE as fallback for NEGOTIATED_GROUP (classical connections)
if [ -z "$NEGOTIATED_GROUP" ] && [ -n "$KEY_EXCHANGE" ]; then
    NEGOTIATED_GROUP="$KEY_EXCHANGE"
fi

echo "  Protocol:         ${PROTOCOL:-unknown}"
echo "  Cipher:           ${CIPHER:-unknown}"
echo "  Negotiated Group: ${NEGOTIATED_GROUP:-unknown}"

# Check if ML-KEM was used (should NOT be, since we forced classical)
if [[ "$NEGOTIATED_GROUP" == *"MLKEM"* ]] || [[ "$NEGOTIATED_GROUP" == *"mlkem"* ]]; then
    echo -e "  Key Exchange:     ${GREEN}★ ML-KEM HYBRID (Quantum-Safe!)${NC}"
    PQC_KEY_EXCHANGE=true
else
    echo -e "  Key Exchange:     ${RED}✗ ${KEY_EXCHANGE:-$NEGOTIATED_GROUP} (NOT quantum-safe!)${NC}"
    PQC_KEY_EXCHANGE=false
fi

# Get server certificate details
print_header "Server Certificate"

CERT_OUTPUT=$(echo | openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -servername "$SERVER_HOST" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)

# Extract public key info
KEY_ALGO=$(echo "$CERT_OUTPUT" | grep "Public Key Algorithm:" | head -1 | sed 's/.*: //')
KEY_SIZE=$(echo "$CERT_OUTPUT" | grep -E "(Public-Key:)" | grep -oE '\([0-9]+ bit\)' | tr -d '()')

# Extract signature algorithm
SIG_ALGO=$(echo "$CERT_OUTPUT" | grep "Signature Algorithm:" | head -1 | sed 's/.*: //')

echo "  Public Key:       ${KEY_ALGO:-unknown} ${KEY_SIZE}"
echo "  Signature:        ${SIG_ALGO:-unknown}"

# Call the endpoint
print_header "GET /hello"

RESPONSE=$(curl --silent --insecure "https://$SERVER_HOST:$SERVER_PORT/hello")
echo "  $RESPONSE"

# Get crypto info from server
print_header "Server Crypto Info"

CRYPTO_INFO=$(curl --silent --insecure "https://$SERVER_HOST:$SERVER_PORT/crypto/info" 2>/dev/null)
if [ -n "$CRYPTO_INFO" ]; then
    echo "$CRYPTO_INFO" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tls = d.get('tls', {})
    pqc = d.get('pqc', {})
    kex = tls.get('keyExchange', {})
    auth = tls.get('authentication', {})
    print(f\"  TLS Provider:     {tls.get('provider', 'unknown')}\")
    print(f\"  Key Exchange:     {kex.get('algorithm', 'unknown')} (quantum-safe: {kex.get('quantumSafe', False)})\")
    print(f\"  Authentication:   {auth.get('algorithm', 'unknown')} (quantum-safe: {auth.get('quantumSafe', False)})\")
    print(f\"  Available PQC:    {', '.join(pqc.get('availableAlgorithms', []))}\")
except:
    print('  (Could not parse crypto info)')
" 2>/dev/null || echo "  (Server returned: $CRYPTO_INFO)"
fi

# Summary
echo ""
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Summary: Classical TLS Connection (NOT Quantum-Safe)${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$PQC_KEY_EXCHANGE" = true ]; then
    echo -e "  ${GREEN}✓ Key Exchange: ML-KEM hybrid (X25519 + ML-KEM-768)${NC}"
    echo "    → Quantum-safe key establishment"
    echo "    → Protected against 'harvest now, decrypt later' attacks"
else
    echo -e "  ${RED}✗ Key Exchange: Classical ${NEGOTIATED_GROUP:-$KEY_EXCHANGE}${NC}"
    echo "    → NOT quantum-safe"
    echo -e "    → ${YELLOW}Vulnerable to 'harvest now, decrypt later' attacks${NC}"
fi

echo ""
echo "  ✓ TLS 1.3 with strong cipher suite"
echo "  ✓ Server supports PQC (client forced classical fallback)"
echo "  ○ Authentication: ECDSA (classical)"
echo ""
echo -e "  ${YELLOW}This demonstrates crypto agility - the server accepts both${NC}"
echo -e "  ${YELLOW}PQC and classical clients for backward compatibility.${NC}"
echo ""
echo "  Run ./scripts/client-demo.sh for PQC-safe connection."
echo ""

