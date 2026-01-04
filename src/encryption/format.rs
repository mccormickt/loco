//! Rails-compatible encrypted value format
//!
//! This module provides serialization/deserialization for encrypted values
//! in a format compatible with Rails ActiveRecord Encryption.
//!
//! # Format
//!
//! Encrypted values are stored as JSON:
//! ```json
//! {
//!   "p": "base64-encoded-ciphertext",
//!   "h": {
//!     "iv": "base64-encoded-iv",
//!     "at": "base64-encoded-auth-tag",
//!     "kid": "optional-key-id"
//!   }
//! }
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::errors::{EncryptionError, EncryptionResult};

/// Headers for encrypted value metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedHeaders {
    /// Base64-encoded initialization vector (nonce)
    pub iv: String,

    /// Base64-encoded authentication tag
    pub at: String,

    /// Optional key identifier for key rotation support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Rails-compatible encrypted value structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    /// Base64-encoded ciphertext (payload)
    pub p: String,

    /// Headers containing IV, auth tag, and optional key ID
    pub h: EncryptedHeaders,
}

impl EncryptedValue {
    /// Create a new encrypted value from raw components
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data bytes
    /// * `iv` - The initialization vector (nonce) bytes
    /// * `auth_tag` - The authentication tag bytes
    /// * `key_id` - Optional key identifier
    #[must_use]
    pub fn new(ciphertext: &[u8], iv: &[u8], auth_tag: &[u8], key_id: Option<String>) -> Self {
        Self {
            p: BASE64.encode(ciphertext),
            h: EncryptedHeaders {
                iv: BASE64.encode(iv),
                at: BASE64.encode(auth_tag),
                kid: key_id,
            },
        }
    }

    /// Parse an encrypted value from a JSON string
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or missing required fields
    pub fn from_json(json: &str) -> EncryptionResult<Self> {
        serde_json::from_str(json).map_err(|e| {
            EncryptionError::InvalidFormat(format!("failed to parse encrypted value: {e}"))
        })
    }

    /// Serialize to a JSON string
    ///
    /// # Errors
    /// Returns an error if serialization fails
    pub fn to_json(&self) -> EncryptionResult<String> {
        serde_json::to_string(self).map_err(EncryptionError::from)
    }

    /// Get the raw ciphertext bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn ciphertext(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.p).map_err(EncryptionError::from)
    }

    /// Get the initialization vector bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn iv(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.h.iv).map_err(EncryptionError::from)
    }

    /// Get the authentication tag bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn auth_tag(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.h.at).map_err(EncryptionError::from)
    }

    /// Get the key identifier if present
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.h.kid.as_deref()
    }
}

/// Check if a string looks like an encrypted value (JSON with expected fields)
#[must_use]
pub fn is_encrypted_format(value: &str) -> bool {
    // Quick check before parsing
    if !value.starts_with('{') || !value.contains("\"p\"") || !value.contains("\"h\"") {
        return false;
    }
    EncryptedValue::from_json(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_value_creation() {
        let ciphertext = b"encrypted data";
        let iv = b"123456789012"; // 12 bytes for AES-GCM
        let auth_tag = b"0123456789abcdef"; // 16 bytes

        let encrypted = EncryptedValue::new(ciphertext, iv, auth_tag, None);

        assert_eq!(encrypted.ciphertext().unwrap(), ciphertext);
        assert_eq!(encrypted.iv().unwrap(), iv);
        assert_eq!(encrypted.auth_tag().unwrap(), auth_tag);
        assert!(encrypted.key_id().is_none());
    }

    #[test]
    fn test_encrypted_value_with_key_id() {
        let ciphertext = b"data";
        let iv = b"123456789012";
        let auth_tag = b"0123456789abcdef";

        let encrypted = EncryptedValue::new(ciphertext, iv, auth_tag, Some("primary".to_string()));

        assert_eq!(encrypted.key_id(), Some("primary"));
    }

    #[test]
    fn test_json_round_trip() {
        let ciphertext = b"test data";
        let iv = b"123456789012";
        let auth_tag = b"0123456789abcdef";

        let original = EncryptedValue::new(ciphertext, iv, auth_tag, Some("key1".to_string()));
        let json = original.to_json().unwrap();
        let parsed = EncryptedValue::from_json(&json).unwrap();

        assert_eq!(parsed.ciphertext().unwrap(), ciphertext);
        assert_eq!(parsed.iv().unwrap(), iv);
        assert_eq!(parsed.auth_tag().unwrap(), auth_tag);
        assert_eq!(parsed.key_id(), Some("key1"));
    }

    #[test]
    fn test_rails_compatible_format() {
        // Example Rails-format JSON
        let rails_json =
            r#"{"p":"dGVzdCBkYXRh","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;

        let parsed = EncryptedValue::from_json(rails_json).unwrap();
        assert_eq!(parsed.ciphertext().unwrap(), b"test data");
        assert_eq!(parsed.iv().unwrap(), b"123456789012");
    }

    #[test]
    fn test_is_encrypted_format() {
        assert!(is_encrypted_format(
            r#"{"p":"abc","h":{"iv":"def","at":"ghi"}}"#
        ));
        assert!(!is_encrypted_format("plain text"));
        assert!(!is_encrypted_format(r#"{"other": "json"}"#));
        assert!(!is_encrypted_format(""));
    }
}
