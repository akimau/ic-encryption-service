use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use candid::{CandidType, Deserialize};
use hkdf::Hkdf;
use ic_cdk_macros::{query, update};
use sha2::Sha256;

#[derive(CandidType, Deserialize, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub certified_data_snapshot: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub enum EncryptResult {
    Ok(EncryptedData),
    Err(String),
}

#[derive(CandidType, Deserialize)]
pub enum DecryptResult {
    Ok(Vec<u8>),
    Err(String),
}

/// Derives a 256-bit master key using HKDF-SHA256
///
/// This function implements HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869.
/// It combines the canister ID and certified data snapshot to derive a deterministic master key.
///
/// # Arguments
/// * `canister_id` - The unique identifier of the canister
/// * `certified_data_snapshot` - The certified data at the time of encryption
///
/// # Returns
/// A 32-byte (256-bit) master key suitable for AES-256-GCM encryption
fn derive_master_key(canister_id: &[u8], certified_data_snapshot: &[u8]) -> Result<[u8; 32], String> {
    // Combine canister ID and certified data as input key material (IKM)
    let mut ikm = Vec::new();
    ikm.extend_from_slice(canister_id);
    ikm.extend_from_slice(certified_data_snapshot);

    // HKDF with salt and info
    let salt = b"CanisterMasterKey";
    let info = b"AES-256-GCM";

    // Perform HKDF-Extract and HKDF-Expand
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut master_key = [0u8; 32];
    hk.expand(info, &master_key)
        .map_err(|e| format!("HKDF expansion failed: {:?}", e))?;

    Ok(master_key)
}

/// Encrypts plaintext using AES-256-GCM
///
/// This function performs authenticated encryption:
/// 1. Derives a master key from the caller's canister ID and certified data snapshot using HKDF
/// 2. Generates a random 96-bit (12-byte) nonce/IV
/// 3. Encrypts the plaintext with AES-256-GCM
/// 4. Returns the encrypted data structure containing ciphertext, IV, tag, and certified data snapshot
///
/// # Arguments
/// * `certified_data_snapshot` - The certified data at the time of encryption
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// EncryptResult containing either the EncryptedData or an error message
///
/// # Security Notes
/// - Each encryption generates a unique random IV
/// - The authentication tag ensures data integrity and authenticity
/// - The certified data snapshot is stored to enable deterministic key rederivation
/// - The caller's canister ID is automatically retrieved and used for key derivation
#[update]
fn encrypt(
    certified_data_snapshot: Vec<u8>,
    plaintext: Vec<u8>,
) -> EncryptResult {
    // Step 1: Get the caller's canister ID
    let caller = ic_cdk::api::caller();
    let canister_id = caller.as_slice();

    // Step 2: Derive the master key using HKDF
    let master_key = match derive_master_key(canister_id, &certified_data_snapshot) {
        Ok(key) => key,
        Err(e) => return EncryptResult::Err(format!("Key derivation failed: {}", e)),
    };

    // Step 3: Initialize AES-256-GCM cipher
    let cipher = match Aes256Gcm::new_from_slice(&master_key) {
        Ok(c) => c,
        Err(e) => return EncryptResult::Err(format!("Cipher initialization failed: {:?}", e)),
    };

    // Step 4: Generate random 96-bit (12-byte) nonce/IV
    // This is the recommended nonce size for AES-GCM
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Step 5: Encrypt the plaintext
    // AES-GCM returns ciphertext || authentication_tag (last 16 bytes are the tag)
    let ciphertext_with_tag = match cipher.encrypt(&nonce, plaintext.as_ref()) {
        Ok(ct) => ct,
        Err(e) => return EncryptResult::Err(format!("Encryption failed: {:?}", e)),
    };

    // Step 6: Split ciphertext and authentication tag
    // The aes-gcm crate appends the 16-byte tag to the end of the ciphertext
    let tag_start = ciphertext_with_tag.len().saturating_sub(16);
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let tag = ciphertext_with_tag[tag_start..].to_vec();

    // Step 7: Return the encrypted data
    EncryptResult::Ok(EncryptedData {
        ciphertext,
        iv: nonce.to_vec(),
        tag,
        certified_data_snapshot,
    })
}

/// Decrypts ciphertext using AES-256-GCM
///
/// This function performs authenticated decryption:
/// 1. Derives the master key from the caller's canister ID and stored certified data snapshot using HKDF
/// 2. Verifies the authentication tag
/// 3. Decrypts the ciphertext with AES-256-GCM using the stored IV
/// 4. Returns the plaintext data
///
/// # Arguments
/// * `encrypted_data` - The EncryptedData structure containing ciphertext, IV, tag, and snapshot
///
/// # Returns
/// DecryptResult containing either the plaintext or an error message
///
/// # Security Notes
/// - Authentication tag is verified BEFORE decryption (prevents padding oracle attacks)
/// - Returns an error if tag verification fails
/// - Uses the stored certified data snapshot to derive the same key used for encryption
/// - The caller's canister ID is automatically retrieved and must match the one used during encryption
#[update]
fn decrypt(encrypted_data: EncryptedData) -> DecryptResult {
    // Step 1: Get the caller's canister ID
    let caller = ic_cdk::api::caller();
    let canister_id = caller.as_slice();

    // Step 2: Derive the master key using the stored certified data snapshot
    let master_key = match derive_master_key(canister_id, &encrypted_data.certified_data_snapshot) {
        Ok(key) => key,
        Err(e) => return DecryptResult::Err(format!("Key derivation failed: {}", e)),
    };

    // Step 3: Initialize AES-256-GCM cipher
    let cipher = match Aes256Gcm::new_from_slice(&master_key) {
        Ok(c) => c,
        Err(e) => return DecryptResult::Err(format!("Cipher initialization failed: {:?}", e)),
    };

    // Step 4: Validate and reconstruct nonce from IV
    if encrypted_data.iv.len() != 12 {
        return DecryptResult::Err("Invalid IV length, expected 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&encrypted_data.iv);

    // Step 5: Reconstruct ciphertext with authentication tag
    // The aes-gcm crate expects ciphertext || tag as input
    let mut ciphertext_with_tag = encrypted_data.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&encrypted_data.tag);

    // Step 6: Decrypt and verify authentication tag
    // The decrypt operation will fail if the tag verification fails
    match cipher.decrypt(nonce, ciphertext_with_tag.as_ref()) {
        Ok(plaintext) => DecryptResult::Ok(plaintext),
        Err(_) => DecryptResult::Err(
            "Decryption failed: authentication tag verification failed. \
             The data may have been tampered with or the wrong key was used.".to_string()
        ),
    }
}

// Export Candid interface
ic_cdk::export_candid!();
