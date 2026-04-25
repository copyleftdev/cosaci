#!/usr/bin/env bash
# Bootstrap demo certs for the Compose stack. Generates:
#   /certs/ca.pem            — demo CA cert
#   /certs/ca.key.pem        — demo CA private key (kept on the volume
#                              for re-issuing certs; not used by coord
#                              or agents at runtime)
#   /certs/server.pem        — coordinator cert (CN=cosaci.local)
#   /certs/server.key.pem    — coordinator private key
#   /certs/agent-N.pem       — agent N cert (CN=agent-N) for N in 0..FLEET-1
#   /certs/agent-N.key.pem   — agent N private key
#
# Idempotent: skips generation if /certs/ca.pem already exists.
#
# This is for the demo Compose stack only. Production deployments are
# expected to use the operator's existing PKI. No private keys from
# this script should ever leave the demo volume.

set -euo pipefail

FLEET="${FLEET:-5}"
CERT_DIR="${CERT_DIR:-/certs}"
SERVER_NAME="${SERVER_NAME:-cosaci.local}"
DAYS="${DAYS:-365}"

mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/ca.pem" ]]; then
    echo "[bootstrap] $CERT_DIR/ca.pem exists; skipping (delete the volume to regenerate)"
    exit 0
fi

echo "[bootstrap] generating demo CA"
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/ca.key.pem"
openssl req -x509 -new -nodes \
    -key "$CERT_DIR/ca.key.pem" \
    -sha256 -days "$DAYS" \
    -subj "/CN=cosaci-demo-ca" \
    -out "$CERT_DIR/ca.pem"

issue_cert() {
    local name="$1"
    local cn="$2"
    local extra_san="${3:-}"

    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/$name.key.pem"

    local cnf
    cnf=$(mktemp)
    cat > "$cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $cn

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF
    if [[ -n "$extra_san" ]]; then
        echo "subjectAltName = $extra_san" >> "$cnf"
    fi

    openssl req -new \
        -key "$CERT_DIR/$name.key.pem" \
        -config "$cnf" \
        -out "$CERT_DIR/$name.csr"

    openssl x509 -req \
        -in "$CERT_DIR/$name.csr" \
        -CA "$CERT_DIR/ca.pem" \
        -CAkey "$CERT_DIR/ca.key.pem" \
        -CAcreateserial \
        -out "$CERT_DIR/$name.pem" \
        -days "$DAYS" \
        -sha256 \
        -extensions v3_req \
        -extfile "$cnf"

    rm -f "$cnf" "$CERT_DIR/$name.csr"
}

echo "[bootstrap] issuing server cert (CN=$SERVER_NAME)"
issue_cert "server" "$SERVER_NAME" "DNS:$SERVER_NAME, DNS:coordinator, DNS:localhost, IP:127.0.0.1"

for ((i = 0; i < FLEET; i++)); do
    echo "[bootstrap] issuing agent-$i cert"
    issue_cert "agent-$i" "agent-$i"
done

echo "[bootstrap] done — $FLEET agent(s) + 1 server enrolled in $CERT_DIR"
ls -la "$CERT_DIR"
