//! Key provider trait and implementations
//!
//! This module defines the `KeyProvider` trait for abstracting encryption key management,
//! and provides a default implementation that reads keys from Loco's configuration.

use hkdf::Hkdf;
use sha2::Sha256;

use super::{
    cipher::{parse_hex_key, KEY_SIZE},
    config::EncryptionConfig,
    errors::{EncryptionError, EncryptionResult},
};

/// Trait for providing encryption keys
///
/// Implement this trait to create custom key providers (e.g., HashiCorp Vault, AWS KMS).
pub trait KeyProvider: Send + Sync {
    /// Get the primary encryption key as raw bytes
    ///
    /// # Errors
    /// Returns an error if the key is not available or invalid
    fn get_encryption_key(&self) -> EncryptionResult<Vec<u8>>;

    /// Get the key identifier for the primary key
    ///
    /// Used for key rotation support. Returns `None` if not tracking key IDs.
    fn get_key_id(&self) -> Option<String> {
        None
    }

    /// Get a derived key for a specific field
    ///
    /// Provides additional security by using field-specific keys derived from the master key.
    /// Default implementation returns the primary key without derivation.
    ///
    /// # Errors
    /// Returns an error if key derivation fails
    fn get_field_key(&self, _field_name: &str) -> EncryptionResult<Vec<u8>> {
        self.get_encryption_key()
    }

    /// Get all keys for decryption (primary + previous keys for rotation)
    ///
    /// Returns a list of (key_bytes, key_id) tuples. The system will try
    /// decrypting with each key until one succeeds.
    ///
    /// # Errors
    /// Returns an error if keys cannot be retrieved
    fn get_decryption_keys(&self) -> EncryptionResult<Vec<(Vec<u8>, Option<String>)>> {
        let primary = self.get_encryption_key()?;
        let key_id = self.get_key_id();
        Ok(vec![(primary, key_id)])
    }
}

/// Default key provider that reads from Loco configuration
///
/// This provider parses encryption keys from the application's YAML configuration,
/// which supports environment variable templating via `{{ get_env(...) }}`.
#[derive(Debug, Clone)]
pub struct ConfigKeyProvider {
    config: EncryptionConfig,
    primary_key: Vec<u8>,
    previous_keys: Vec<Vec<u8>>,
    salt: Option<Vec<u8>>,
}

impl ConfigKeyProvider {
    /// Create a new config key provider
    ///
    /// # Errors
    /// Returns an error if the primary key is missing or invalid
    pub fn new(config: EncryptionConfig) -> EncryptionResult<Self> {
        if !config.has_primary_key() {
            return Err(EncryptionError::NotConfigured(
                "primary_key is required".to_string(),
            ));
        }

        let primary_key = parse_hex_key(&config.primary_key)?;

        // Parse previous keys, skipping invalid ones with a warning
        let previous_keys: Vec<Vec<u8>> = config
            .valid_previous_keys()
            .iter()
            .filter_map(|k| parse_hex_key(k).ok())
            .collect();

        // Parse salt if key derivation is enabled
        let salt = if config.is_key_derivation_enabled() {
            config
                .key_derivation
                .as_ref()
                .and_then(|kd| kd.salt.as_ref())
                .map(|s| parse_hex_key(s))
                .transpose()?
        } else {
            None
        };

        Ok(Self {
            config,
            primary_key,
            previous_keys,
            salt,
        })
    }

    /// Derive a field-specific key using HKDF
    fn derive_key(&self, master_key: &[u8], field_name: &str) -> EncryptionResult<Vec<u8>> {
        let salt = self.salt.as_ref().ok_or_else(|| {
            EncryptionError::KeyDerivation("salt is required for key derivation".to_string())
        })?;

        // Use HKDF to derive a field-specific key
        let hk = Hkdf::<Sha256>::new(Some(salt), master_key);

        let mut derived_key = vec![0u8; KEY_SIZE];
        hk.expand(field_name.as_bytes(), &mut derived_key)
            .map_err(|e| EncryptionError::KeyDerivation(e.to_string()))?;

        Ok(derived_key)
    }
}

impl KeyProvider for ConfigKeyProvider {
    fn get_encryption_key(&self) -> EncryptionResult<Vec<u8>> {
        Ok(self.primary_key.clone())
    }

    fn get_key_id(&self) -> Option<String> {
        Some("primary".to_string())
    }

    fn get_field_key(&self, field_name: &str) -> EncryptionResult<Vec<u8>> {
        if self.config.is_key_derivation_enabled() {
            self.derive_key(&self.primary_key, field_name)
        } else {
            Ok(self.primary_key.clone())
        }
    }

    fn get_decryption_keys(&self) -> EncryptionResult<Vec<(Vec<u8>, Option<String>)>> {
        let mut keys = Vec::with_capacity(1 + self.previous_keys.len());

        // Primary key first
        keys.push((self.primary_key.clone(), Some("primary".to_string())));

        // Then previous keys (for rotation support)
        for (i, key) in self.previous_keys.iter().enumerate() {
            keys.push((key.clone(), Some(format!("previous_{i}"))));
        }

        Ok(keys)
    }
}

/// A simple key provider for testing or when keys are already in memory
#[derive(Debug, Clone)]
pub struct StaticKeyProvider {
    key: Vec<u8>,
    key_id: Option<String>,
}

impl StaticKeyProvider {
    /// Create a new static key provider from raw key bytes
    ///
    /// # Errors
    /// Returns an error if the key is not 32 bytes
    pub fn new(key: Vec<u8>, key_id: Option<String>) -> EncryptionResult<Self> {
        if key.len() != KEY_SIZE {
            return Err(EncryptionError::InvalidKey(format!(
                "key must be {KEY_SIZE} bytes, got {}",
                key.len()
            )));
        }
        Ok(Self { key, key_id })
    }

    /// Create from a hex-encoded key string
    ///
    /// # Errors
    /// Returns an error if the hex string is invalid
    pub fn from_hex(hex: &str, key_id: Option<String>) -> EncryptionResult<Self> {
        let key = parse_hex_key(hex)?;
        Self::new(key, key_id)
    }
}

impl KeyProvider for StaticKeyProvider {
    fn get_encryption_key(&self) -> EncryptionResult<Vec<u8>> {
        Ok(self.key.clone())
    }

    fn get_key_id(&self) -> Option<String> {
        self.key_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> EncryptionConfig {
        EncryptionConfig {
            // 64 hex chars = 32 bytes
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![],
            key_derivation: None,
        }
    }

    #[test]
    fn test_config_key_provider_basic() {
        let config = test_config();
        let provider = ConfigKeyProvider::new(config).unwrap();

        let key = provider.get_encryption_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(key[0], 0x00);
        assert_eq!(key[31], 0x1f);
    }

    #[test]
    fn test_config_key_provider_missing_key() {
        let config = EncryptionConfig {
            primary_key: "".to_string(),
            previous_keys: vec![],
            key_derivation: None,
        };

        assert!(ConfigKeyProvider::new(config).is_err());
    }

    #[test]
    fn test_config_key_provider_with_previous_keys() {
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![
                "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string(),
            ],
            key_derivation: None,
        };

        let provider = ConfigKeyProvider::new(config).unwrap();
        let decryption_keys = provider.get_decryption_keys().unwrap();

        assert_eq!(decryption_keys.len(), 2);
        assert_eq!(decryption_keys[0].1, Some("primary".to_string()));
        assert_eq!(decryption_keys[1].1, Some("previous_0".to_string()));
    }

    #[test]
    fn test_config_key_provider_key_derivation() {
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![],
            key_derivation: Some(super::super::config::KeyDerivationConfig {
                enabled: true,
                salt: Some(
                    "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb".to_string(),
                ),
            }),
        };

        let provider = ConfigKeyProvider::new(config).unwrap();

        // Field-specific keys should be different from primary key
        let primary = provider.get_encryption_key().unwrap();
        let field_key = provider.get_field_key("ssn").unwrap();

        assert_ne!(primary, field_key);
        assert_eq!(field_key.len(), KEY_SIZE);

        // Same field should get same derived key
        let field_key2 = provider.get_field_key("ssn").unwrap();
        assert_eq!(field_key, field_key2);

        // Different fields should get different keys
        let other_field_key = provider.get_field_key("credit_card").unwrap();
        assert_ne!(field_key, other_field_key);
    }

    #[test]
    fn test_static_key_provider() {
        let key = vec![0u8; 32];
        let provider = StaticKeyProvider::new(key.clone(), Some("test".to_string())).unwrap();

        assert_eq!(provider.get_encryption_key().unwrap(), key);
        assert_eq!(provider.get_key_id(), Some("test".to_string()));
    }

    #[test]
    fn test_static_key_provider_from_hex() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let provider = StaticKeyProvider::from_hex(hex, None).unwrap();

        let key = provider.get_encryption_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_static_key_provider_invalid_size() {
        let short_key = vec![0u8; 16];
        assert!(StaticKeyProvider::new(short_key, None).is_err());
    }
}
