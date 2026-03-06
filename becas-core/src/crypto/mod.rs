//! # Crypto Engine
//!
//! Provides cryptographic services for BECAS:
//! - **Identity:** Ed25519 keypair for service/node identity
//! - **Encrypted Storage:** AES-256-GCM encrypted volumes
//! - **Key Exchange:** X25519 Diffie-Hellman for secure channels
//! - **Data Masking:** Sensitive data masking for diagnostic logs
//!
//! ## Key Principle
//! PC owner provides storage, but **cannot read service data**.
//! Data is encrypted with keys only the service (and BECAS Layer) knows.
//! Owner can see masked logs (Level 2) but never raw data.

use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use rand::RngCore;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// ─────────────────────────────────────────────
// Identity (Ed25519 Keypair)
// ─────────────────────────────────────────────

/// A BECAS identity backed by Ed25519 keypair.
/// Every service and node has a unique identity.
/// Identity = public key = address (no central authority needed).
#[derive(Debug)]
pub struct Identity {
    /// Unique identifier derived from public key
    pub id: String,
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    pub verifying_key: VerifyingKey,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Identity ID is first 16 hex chars of SHA-256(public_key)
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.as_bytes());
        let hash = hasher.finalize();
        let id = hex::encode(&hash[..8]);

        Self {
            id,
            signing_key,
            verifying_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature from any public key
    pub fn verify(public_key: &VerifyingKey, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        let sig_bytes: [u8; 64] = signature_bytes.try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        public_key.verify(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Get public key bytes for sharing
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.as_bytes().to_vec()
    }

    /// Export identity to serializable format (ONLY for secure backup)
    pub fn export(&self) -> IdentityExport {
        IdentityExport {
            id: self.id.clone(),
            signing_key: self.signing_key.to_bytes().to_vec(),
            verifying_key: self.verifying_key.as_bytes().to_vec(),
        }
    }

    /// Import identity from exported format
    pub fn import(export: &IdentityExport) -> Result<Self> {
        let sk_bytes: [u8; 32] = export.signing_key.as_slice().try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid signing key length".into()))?;
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            id: export.id.clone(),
            signing_key,
            verifying_key,
        })
    }
}

/// Serializable identity export (for secure storage/backup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityExport {
    pub id: String,
    #[serde(with = "hex_serde")]
    pub signing_key: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub verifying_key: Vec<u8>,
}

/// Simple hex serialization helper
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        ::hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ─────────────────────────────────────────────
// Encrypted Volume
// ─────────────────────────────────────────────

/// An encrypted storage volume for a service.
/// Data is encrypted with AES-256-GCM before writing to disk.
/// PC owner cannot read the data — only the service can.
pub struct EncryptedVolume {
    /// Volume identifier
    pub id: Uuid,
    /// Path to encrypted data on disk
    path: PathBuf,
    /// Encryption key (derived from service identity)
    cipher: Aes256Gcm,
}

impl EncryptedVolume {
    /// Create a new encrypted volume
    pub fn new(path: PathBuf) -> Result<Self> {
        // Generate a random encryption key
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        std::fs::create_dir_all(&path)?;

        Ok(Self {
            id: Uuid::new_v4(),
            path,
            cipher,
        })
    }

    /// Create from an existing key (for restoring volumes)
    pub fn from_key(path: PathBuf, key_bytes: &[u8; 32]) -> Result<Self> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        std::fs::create_dir_all(&path)?;

        Ok(Self {
            id: Uuid::new_v4(),
            path,
            cipher,
        })
    }

    /// Encrypt and write data to a file in the volume
    pub fn write(&self, filename: &str, data: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(data)?;
        let file_path = self.path.join(filename);
        std::fs::write(&file_path, &encrypted)?;
        Ok(())
    }

    /// Read and decrypt data from a file in the volume
    pub fn read(&self, filename: &str) -> Result<Vec<u8>> {
        let file_path = self.path.join(filename);
        let encrypted = std::fs::read(&file_path)?;
        self.decrypt(&encrypted)
    }

    /// Check if a file exists in the volume
    pub fn exists(&self, filename: &str) -> bool {
        self.path.join(filename).exists()
    }

    /// Delete a file from the volume
    pub fn delete(&self, filename: &str) -> Result<()> {
        let file_path = self.path.join(filename);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }
        Ok(())
    }

    /// List files in the volume (names only, content is encrypted)
    pub fn list_files(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                files.push(name.to_string());
            }
        }
        Ok(files)
    }

    /// Get volume disk usage in bytes
    pub fn disk_usage(&self) -> Result<u64> {
        let mut total = 0u64;
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            total += entry.metadata()?.len();
        }
        Ok(total)
    }

    // ─── Internal ───

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext (nonce is not secret)
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Data too short".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

// ─────────────────────────────────────────────
// Crypto Engine
// ─────────────────────────────────────────────

/// The main crypto engine for BECAS.
/// Manages identities, volumes, and cryptographic operations.
pub struct CryptoEngine {
    /// BECAS node identity (this PC's identity in the network)
    node_identity: Identity,
    /// Base path for crypto data
    base_dir: PathBuf,
}

impl CryptoEngine {
    /// Create a new crypto engine, generating a node identity
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_dir)?;

        let identity_path = base_dir.join("node_identity.json");
        let node_identity = if identity_path.exists() {
            // Load existing identity
            let data = std::fs::read_to_string(&identity_path)?;
            let export: IdentityExport = serde_json::from_str(&data)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
            Identity::import(&export)?
        } else {
            // Generate new identity
            let identity = Identity::generate();
            let export = identity.export();
            let data = serde_json::to_string_pretty(&export)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
            std::fs::write(&identity_path, data)?;
            tracing::info!(id = %identity.id, "Generated new node identity");
            identity
        };

        Ok(Self {
            node_identity,
            base_dir,
        })
    }

    /// Get this node's identity
    pub fn node_identity(&self) -> &Identity {
        &self.node_identity
    }

    /// Create an encrypted volume for a service
    pub fn create_volume(&self, service_id: &Uuid) -> Result<EncryptedVolume> {
        let vol_path = self.base_dir.join("volumes").join(service_id.to_string());
        EncryptedVolume::new(vol_path)
    }

    /// Generate a service identity
    pub fn generate_service_identity(&self) -> Identity {
        Identity::generate()
    }

    /// Hash data with SHA-256
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Mask sensitive data for diagnostic logs
    /// "user@email.com" → "us***@em***.com"
    /// "John Smith" → "Jo*** Sm***"
    pub fn mask_sensitive(input: &str) -> String {
        if input.len() <= 3 {
            return "***".to_string();
        }

        if input.contains('@') {
            // Email masking
            let parts: Vec<&str> = input.split('@').collect();
            if parts.len() == 2 {
                let local = if parts[0].len() > 2 {
                    format!("{}***", &parts[0][..2])
                } else {
                    "***".to_string()
                };
                let domain_parts: Vec<&str> = parts[1].split('.').collect();
                let domain = if !domain_parts.is_empty() && domain_parts[0].len() > 2 {
                    format!("{}***.{}", &domain_parts[0][..2],
                        domain_parts.last().unwrap_or(&"***"))
                } else {
                    "***".to_string()
                };
                return format!("{}@{}", local, domain);
            }
        }

        // Generic masking: show first 2 chars of each word
        input.split_whitespace()
            .map(|word| {
                if word.len() > 2 {
                    format!("{}***", &word[..2])
                } else {
                    "***".to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// hex crate is used via Cargo dependency

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let id = Identity::generate();
        assert!(!id.id.is_empty());
        assert_eq!(id.id.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_identity_sign_verify() {
        let id = Identity::generate();
        let message = b"Hello BECAS!";
        let signature = id.sign(message);

        assert!(Identity::verify(&id.verifying_key, message, &signature).is_ok());
    }

    #[test]
    fn test_identity_wrong_signature() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let message = b"Hello BECAS!";
        let signature = id1.sign(message);

        // Verify with wrong key should fail
        assert!(Identity::verify(&id2.verifying_key, message, &signature).is_err());
    }

    #[test]
    fn test_identity_export_import() {
        let original = Identity::generate();
        let exported = original.export();
        let imported = Identity::import(&exported).unwrap();

        assert_eq!(original.id, imported.id);
        assert_eq!(original.public_key_bytes(), imported.public_key_bytes());

        // Imported key should produce same signatures
        let msg = b"test";
        let sig = imported.sign(msg);
        assert!(Identity::verify(&original.verifying_key, msg, &sig).is_ok());
    }

    #[test]
    fn test_encrypted_volume_write_read() {
        let dir = tempfile::tempdir().unwrap();
        let vol = EncryptedVolume::new(dir.path().join("vol")).unwrap();

        let data = b"secret database content";
        vol.write("test.dat", data).unwrap();

        let decrypted = vol.read("test.dat").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypted_volume_data_is_encrypted_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vol = EncryptedVolume::new(dir.path().join("vol")).unwrap();

        let data = b"this should not be readable on disk";
        vol.write("secret.dat", data).unwrap();

        // Read raw file — should NOT contain plaintext
        let raw = std::fs::read(dir.path().join("vol").join("secret.dat")).unwrap();
        assert_ne!(raw, data);
        assert!(!String::from_utf8_lossy(&raw).contains("this should not be readable"));
    }

    #[test]
    fn test_encrypted_volume_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vol1 = EncryptedVolume::new(dir.path().join("vol")).unwrap();
        vol1.write("test.dat", b"secret").unwrap();

        // Create volume with different key at same path
        let vol2 = EncryptedVolume::new(dir.path().join("vol2")).unwrap();

        // Copy the encrypted file
        let encrypted = std::fs::read(dir.path().join("vol").join("test.dat")).unwrap();
        std::fs::write(dir.path().join("vol2").join("test.dat"), &encrypted).unwrap();

        // Should fail to decrypt with wrong key
        assert!(vol2.read("test.dat").is_err());
    }

    #[test]
    fn test_mask_email() {
        assert_eq!(CryptoEngine::mask_sensitive("user@email.com"), "us***@em***.com");
    }

    #[test]
    fn test_mask_name() {
        assert_eq!(CryptoEngine::mask_sensitive("John Smith"), "Jo*** Sm***");
    }

    #[test]
    fn test_mask_short() {
        assert_eq!(CryptoEngine::mask_sensitive("ab"), "***");
    }

    #[test]
    fn test_hash() {
        let h1 = CryptoEngine::hash(b"hello");
        let h2 = CryptoEngine::hash(b"hello");
        let h3 = CryptoEngine::hash(b"world");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn test_crypto_engine_creates_identity() {
        let dir = tempfile::tempdir().unwrap();
        let engine = CryptoEngine::new(dir.path().to_path_buf()).unwrap();

        assert!(!engine.node_identity().id.is_empty());

        // Creating again at same path should load existing identity
        let engine2 = CryptoEngine::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(engine.node_identity().id, engine2.node_identity().id);
    }
}
