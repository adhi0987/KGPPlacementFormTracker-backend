#!/usr/bin/env bash
#
# Generates the ECDSA P-256 keypair used to sign PRO entitlement
# tokens.
#
#   private JWK -> Cloudflare secret LICENSE_SIGNING_KEY (never ships)
#   public  JWK -> LICENSE_PUBLIC_JWK in popup.js (ships in the extension)
#
# Requires: openssl, python3.
#
# Usage:
#   ./tools/generate-license-keypair.sh

set -euo pipefail

TMPDIR_KEYPAIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_KEYPAIR"' EXIT

PRIV_PEM="$TMPDIR_KEYPAIR/private.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV_PEM" 2>/dev/null

python3 - "$PRIV_PEM" <<'PY'
import base64
import re
import subprocess
import sys

pem = sys.argv[1]


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


text = subprocess.run(
    ["openssl", "ec", "-in", pem, "-text", "-noout"],
    capture_output=True,
    text=True,
    check=True,
).stdout

pub_hex = "".join(
    re.search(r"pub:\s*\n((?:\s+[0-9a-f:]+\n)+)", text).group(1).split()
).replace(":", "")

priv_hex = "".join(
    re.search(r"priv:\s*\n((?:\s+[0-9a-f:]+\n)+)", text).group(1).split()
).replace(":", "")

assert pub_hex.startswith("04"), "unexpected public point encoding"

x = bytes.fromhex(pub_hex[2:66])
y = bytes.fromhex(pub_hex[66:130])
d = bytes.fromhex(priv_hex.zfill(64))

public_jwk = '{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}' % (b64u(x), b64u(y))
private_jwk = (
    '{"kty":"EC","crv":"P-256","x":"%s","y":"%s","d":"%s"}'
    % (b64u(x), b64u(y), b64u(d))
)

print()
print("=== 1. Cloudflare secret ===")
print("Run this from the worker/ directory, then paste the JSON when prompted:")
print()
print("    npx wrangler secret put LICENSE_SIGNING_KEY")
print()
print("Value (keep this private, never commit it):")
print()
print(private_jwk)
print()
print("=== 2. Extension public key ===")
print("Paste this into LICENSE_PUBLIC_JWK in popup.js:")
print()
print(public_jwk)
print()
PY
