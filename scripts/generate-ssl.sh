#!/bin/bash
# generate-ssl.sh - Generate self-signed SSL certificate for local development
# For production, use Let's Encrypt or your CA

set -e
export MSYS_NO_PATHCONV=1

SSL_DIR="./nginx/ssl"
mkdir -p "$SSL_DIR"

echo "Generating self-signed SSL certificate for local development..."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" \
    -out "$SSL_DIR/cert.pem" \
    -subj "/C=VN/ST=HCM/L=HoChiMinh/O=SecurityScanner/OU=Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "SSL certificate generated at $SSL_DIR"
echo "cert.pem and key.pem are ready for Nginx"
