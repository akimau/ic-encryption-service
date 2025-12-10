# Encryption Service

A Rust-based Internet Computer canister that provides production-grade AES-256-GCM encryption and decryption services.

## Overview

This service provides secure encryption/decryption using:

- **AES-256-GCM**: Authenticated encryption with associated data (AEAD)
- **HKDF-SHA256**: Key derivation function for generating master keys
- **Deterministic key derivation**: Keys are derived from canister ID and certified data snapshots

## Features

- ✅ **Production-grade cryptography**: Uses battle-tested Rust crates (`aes-gcm`, `hkdf`, `sha2`)
- ✅ **Authenticated encryption**: AES-GCM provides both confidentiality and authenticity
- ✅ **Random IV generation**: Each encryption uses a unique 96-bit initialization vector
- ✅ **Deterministic key derivation**: Same inputs always produce the same key
- ✅ **Certified data binding**: Keys are tied to specific certified data states

## API

### `encrypt`

Encrypts plaintext data using AES-256-GCM.

```candid
encrypt : (certified_data_snapshot: blob, plaintext: blob) -> (EncryptResult)
```

**Parameters:**

- `certified_data_snapshot`: The certified data at the time of encryption
- `plaintext`: The data to encrypt

**Returns:**

- `Ok(EncryptedData)`: Contains ciphertext, IV, authentication tag, and certified data snapshot
- `Err(text)`: Error message if encryption fails

**Note:** The caller's canister ID is automatically retrieved using `ic_cdk::api::caller()` and used for key derivation.

### `decrypt`

Decrypts ciphertext data using AES-256-GCM.

```candid
decrypt : (encrypted_data: EncryptedData) -> (DecryptResult)
```

**Parameters:**

- `encrypted_data`: The EncryptedData structure containing ciphertext, IV, tag, and snapshot

**Returns:**

- `Ok(blob)`: The decrypted plaintext
- `Err(text)`: Error message if decryption or authentication fails

**Note:** The caller's canister ID is automatically retrieved and must match the canister that performed the encryption.

## Security Notes

### Key Derivation

- Uses HKDF-SHA256 with salt `"CanisterMasterKey"` and info `"AES-256-GCM"`
- Input key material (IKM) is `caller_id || certified_data_snapshot`
- The caller's canister ID is automatically retrieved via `ic_cdk::api::caller()`
- Produces a 256-bit master key
- Each canister can only decrypt data it encrypted (caller ID must match)

### Encryption

- Each encryption generates a unique random 96-bit IV (optimal for AES-GCM)
- Authentication tag is 128 bits (16 bytes)
- Never reuse an IV with the same key

### Decryption

- Authentication tag is verified BEFORE decryption
- Returns error if tag verification fails (prevents padding oracle attacks)
- Uses constant-time comparisons where applicable

## Building

```bash
# Build the encryption service
dfx build encryption-service

# Deploy locally
dfx deploy encryption-service

# Deploy to mainnet
dfx deploy --network ic encryption-service
```

## Cycle Costs

This service is extremely cost-effective for encryption operations on the Internet Computer:

### Per Operation Cost Estimate

**For encrypting 1 KB of data:**

- **Base update call fee**: 1,200,000 cycles
- **Input data** (~1,064 bytes): ~2,128,000 cycles (2,000 cycles/byte)
- **Random number generation** (`raw_rand()` inter-canister call): ~260,000 cycles (base fee)
- **Computation** (AES-256-GCM + HKDF): ~10-50M cycles
- **Total per encrypt operation**: ~13-53M cycles (~$0.000018-0.000072 USD)

**For decrypting 1 KB of data:**

- **Base update call fee**: 1,200,000 cycles
- **Input data** (~1,092 bytes including encrypted structure): ~2,184,000 cycles (2,000 cycles/byte)
- **Computation** (AES-256-GCM + HKDF): ~10-50M cycles
- **Total per decrypt operation**: ~13-53M cycles (~$0.000018-0.000072 USD)

### Volume Pricing Examples

- **1,000 encryptions/day**: ~13-53 billion cycles/year (~$0.018-0.072 USD/year)
- **10,000 encryptions/day**: ~130-530 billion cycles/year (~$0.18-0.72 USD/year)
- **100,000 encryptions/day**: ~1.3-5.3 trillion cycles/year (~$1.76-7.16 USD/year)

### Cost Breakdown

- **Update call base fee**: 1.2M cycles (fixed per call)
- **Ingress bytes**: 2K cycles per byte
- **`raw_rand()` call** (encrypt only): 260K cycles for secure random IV generation
- **No storage costs**: Service doesn't store data, only processes it
- **Scales with data size**: Larger plaintexts increase ingress costs linearly

**Note**: 1 trillion cycles = 1 XDR ≈ $1.35 USD (as of 2025)

This is significantly cheaper than traditional cloud encryption services (e.g., AWS KMS charges ~$0.03 per 10,000 requests).

## Dependencies

- `aes-gcm` (0.10): AES-256-GCM implementation
- `hkdf` (0.12): HMAC-based Key Derivation Function
- `sha2` (0.10): SHA-256 implementation
- `ic-cdk` (0.15): Internet Computer Canister Development Kit
- `candid` (0.10): Candid serialization

## Testing

```bash
# Run Rust unit tests
cargo test --target wasm32-unknown-unknown

# Test via dfx
dfx canister call encryption-service encrypt '(blob "certified-data", blob "plaintext")'
```

## License

MIT
