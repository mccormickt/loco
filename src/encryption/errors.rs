//! Encryption error types
//!
//! This module defines error types specific to field encryption operations.

use thiserror::Error;

/// Errors that can occur during encryption/decryption operations
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Invalid encryption key format or length
    #[error("invalid encryption key: {0}")]
    InvalidKey(String),

    /// Key not found or not configured
    #[error("encryption key not found: {0}")]
    KeyNotFound(String),

    /// Error during encryption operation
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Error during decryption operation
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid encrypted value format
    #[error("invalid encrypted value format: {0}")]
    InvalidFormat(String),

    /// Base64 encoding/decoding error
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error
    #[error("encryption not configured: {0}")]
    NotConfigured(String),

    /// Key derivation error
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
}

/// Result type for encryption operations
pub type EncryptionResult<T> = std::result::Result<T, EncryptionError>;
