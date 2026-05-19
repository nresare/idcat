#!/bin/sh
# Wrap key material for AWS KMS import using RSA_AES_KEY_WRAP_SHA_256.
# Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
#
# Usage: ./encrypt-key-material.sh <PlaintextKeyMaterial.pem> <WrappingPublicKey.bin>
# Output: EncryptedKeyMaterial.bin in the current directory.
#
# Requires OpenSSL 3.x.

set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <PlaintextKeyMaterial.pem> <WrappingPublicKey.bin>" >&2
    exit 1
fi

PLAINTEXT_KEY_MATERIAL_PEM="$1"
WRAPPING_PUBLIC_KEY="$2"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PLAINTEXT_KEY_MATERIAL="$WORK_DIR/plaintext-key-material.der"
AES_KEY="$WORK_DIR/aes-key.bin"
KEY_MATERIAL_WRAPPED="$WORK_DIR/key-material-wrapped.bin"
AES_KEY_WRAPPED="$WORK_DIR/aes-key-wrapped.bin"

# Step 0: convert PEM to DER format.
openssl pkcs8 -topk8 -outform der -nocrypt \
    -in "$PLAINTEXT_KEY_MATERIAL_PEM" \
    -out "$PLAINTEXT_KEY_MATERIAL"

# Step 1: generate a 256-bit AES key.
openssl rand -out "$AES_KEY" 32

# Step 2: wrap the key material with the AES key (RFC 5649 AES Key Wrap with Padding).
openssl enc -id-aes256-wrap-pad \
    -K "$(xxd -p < "$AES_KEY" | tr -d '\n')" \
    -iv A65959A6 \
    -in "$PLAINTEXT_KEY_MATERIAL" \
    -out "$KEY_MATERIAL_WRAPPED"

# Step 3: encrypt the AES key with the KMS wrapping public key using RSAES_OAEP_SHA_256.
openssl pkeyutl \
    -encrypt \
    -in "$AES_KEY" \
    -out "$AES_KEY_WRAPPED" \
    -inkey "$WRAPPING_PUBLIC_KEY" \
    -keyform DER \
    -pubin \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256

# Step 4: concatenate wrapped AES key || wrapped key material.
cat "$AES_KEY_WRAPPED" "$KEY_MATERIAL_WRAPPED" > EncryptedKeyMaterial.bin
