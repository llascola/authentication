#!/usr/bin/env bash
# Run the mailer integration test against a throwaway Mailpit instance.
#
# Provisions Mailpit in Docker with a self-signed STARTTLS certificate, waits
# for its API, runs the `integration`-tagged test in internal/adapter/mailer,
# then tears everything down. Requires docker and openssl on PATH.
set -euo pipefail

CONTAINER=authn-mailpit-it
IMAGE=axllent/mailpit:latest
CERTDIR="$(mktemp -d)"

cleanup() {
	docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
	rm -rf "$CERTDIR"
}
trap cleanup EXIT

echo ">> generating self-signed cert for localhost"
openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$CERTDIR/key.pem" -out "$CERTDIR/cert.pem" \
	-days 1 -subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

echo ">> starting Mailpit ($IMAGE)"
docker run -d --rm --name "$CONTAINER" \
	-p 1025:1025 -p 8025:8025 \
	-v "$CERTDIR:/certs:ro" \
	-e MP_SMTP_TLS_CERT=/certs/cert.pem \
	-e MP_SMTP_TLS_KEY=/certs/key.pem \
	-e MP_SMTP_AUTH_ACCEPT_ANY=1 \
	-e MP_SMTP_AUTH_ALLOW_INSECURE=1 \
	"$IMAGE" >/dev/null

echo ">> waiting for Mailpit API"
for _ in $(seq 1 40); do
	if curl -fs http://localhost:8025/api/v1/info >/dev/null 2>&1; then
		break
	fi
	sleep 0.25
done

echo ">> running integration test"
MAILPIT_SMTP_ADDR=localhost:1025 \
MAILPIT_API_URL=http://localhost:8025 \
	go test -tags=integration -count=1 -run Integration ./internal/adapter/mailer/
