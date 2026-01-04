//! Model Field Encryption
//!
//! This module provides Rails-style ActiveRecord encryption for Loco, using
//! AEAD (Authenticated Encryption with Associated Data) encryption for model fields
//! with AES-256-GCM.
//!
//! # Features
//!
//! - **Automatic encryption on save**: Fields are automatically encrypted using
//!   `ActiveModelBehavior::before_save`
//! - **Explicit decryption on read**: Manual decryption call required (Rust idiom)
//! - **Rails-compatible format**: Uses Rails ActiveRecord Encryption JSON format
//! - **AEAD security**: Uses AES-256-GCM for authenticated encryption
//! - **Flexible key management**: Trait-based key provider system
//! - **Key rotation support**: Configure previous keys for seamless rotation
//! - **Non-deterministic encryption**: Same plaintext produces different ciphertext
//!
//! # Differences from Rails ActiveRecord Encryption
//!
//! - **Encryption**: Automatic (same as Rails) - happens in `before_save` hook
//! - **Decryption**: **Explicit** (unlike Rails) - requires calling `decrypt_fields()`
//!   - Rails: `user.ssn` automatically decrypts
//!   - Loco: `user.ssn` returns encrypted JSON; must call `user.decrypt_fields()` first
//!
//! # Quick Start
//!
//! 1. Add configuration to your `config/*.yaml`:
//!
//! ```yaml
//! encryption:
//!   primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
//! ```
//!
//! 2. Generate a key with: `openssl rand -hex 32`
//!
//! 3. Implement `Encryptable` on your ActiveModel:
//!
//! ```rust,ignore
//! use loco_rs::encryption::Encryptable;
//!
//! impl Encryptable for users::ActiveModel {
//!     fn encrypted_fields() -> Vec<String> {
//!         vec!["ssn".into(), "credit_card".into()]
//!     }
//! }
//! ```
//!
//! 4. Add helper methods on your Model for encrypted save/find:
//!
//! ```rust,ignore
//! impl users::Model {
//!     pub async fn save_encrypted(
//!         active_model: users::ActiveModel,
//!         db: &DatabaseConnection,
//!         ctx: &AppContext,
//!     ) -> Result<Self> {
//!         let provider = ConfigKeyProvider::new(
//!             ctx.config.encryption.clone()
//!                 .ok_or_else(|| Error::string("encryption not configured"))?
//!         )?;
//!         let encrypted = active_model.encrypt_fields(&provider)?;
//!         Ok(encrypted.insert(db).await?)
//!     }
//!
//!     pub async fn find_decrypt(
//!         db: &DatabaseConnection,
//!         id: i32,
//!         ctx: &AppContext,
//!     ) -> Result<Option<Self>> {
//!         let provider = ConfigKeyProvider::new(
//!             ctx.config.encryption.clone()
//!                 .ok_or_else(|| Error::string("encryption not configured"))?
//!         )?;
//!         if let Some(mut model) = users::Entity::find_by_id(id).one(db).await? {
//!             model.decrypt_fields::<users::Entity>(&provider)?;
//!             Ok(Some(model))
//!         } else {
//!             Ok(None)
//!         }
//!     }
//! }
//! ```
//!
//! 5. Use in your controllers:
//!
//! ```rust,ignore
//! // Creating with encryption
//! let user = users::Model::save_encrypted(active_model, &ctx.db, &ctx).await?;
//!
//! // Finding with decryption
//! let user = users::Model::find_decrypt(&ctx.db, 1, &ctx).await?
//!     .ok_or_else(|| Error::NotFound)?;
//! println!("{}", user.ssn); // Decrypted!
//! ```
//!
//! **Note**: SeaORM's `ActiveModelBehavior::before_save` hook does not have access
//! to the `AppContext`, so encryption must be done explicitly before calling save.
//!
//! # Encrypted Value Format
//!
//! Encrypted values are stored as JSON (Rails-compatible):
//!
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
//!
//! # Security Considerations
//!
//! - **Never commit keys to version control**
//! - Use Loco's config system with env var templating
//! - Generate keys with: `openssl rand -hex 32`
//! - Enable key derivation for field-specific keys
//! - Configure `previous_keys` for zero-downtime key rotation

pub mod cipher;
pub mod config;
pub mod encryptable;
pub mod errors;
pub mod format;
pub mod key_provider;

// Re-export main types for convenience
pub use cipher::{decrypt, encrypt, parse_hex_key, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
pub use config::{EncryptionConfig, KeyDerivationConfig};
pub use encryptable::{decrypt_field, encrypt_field, Encryptable, ModelDecryption};
pub use errors::{EncryptionError, EncryptionResult};
pub use format::{is_encrypted_format, EncryptedHeaders, EncryptedValue};
pub use key_provider::{ConfigKeyProvider, KeyProvider, StaticKeyProvider};
