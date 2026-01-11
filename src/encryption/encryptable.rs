//! Encryptable trait for model field encryption
//!
//! This module provides the `Encryptable` trait for marking which fields should be
//! encrypted on an `ActiveModel`, and the `ModelDecryption` trait for decrypting
//! fields on a `Model`.
//!
//! # Convenience Macro
//!
//! Use the `impl_encryptable_fields!` macro to reduce boilerplate:
//!
//! ```rust,ignore
//! use loco_rs::impl_encryptable_fields;
//!
//! // Instead of manually implementing all methods:
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card]);
//! ```
//!
//! # Usage
//!
//! 1. Implement `Encryptable` on your `ActiveModel`:
//!
//! ```rust,ignore
//! use loco_rs::encryption::{Encryptable, EncryptionResult};
//! use sea_orm::ActiveValue;
//!
//! impl Encryptable for users::ActiveModel {
//!     fn encrypted_fields() -> Vec<String> {
//!         vec!["ssn".into(), "credit_card".into()]
//!     }
//!
//!     fn get_set_string_value(&self, field_name: &str) -> Option<String> {
//!         match field_name {
//!             "ssn" => match &self.ssn {
//!                 ActiveValue::Set(v) => Some(v.clone()),
//!                 _ => None,
//!             },
//!             "credit_card" => match &self.credit_card {
//!                 ActiveValue::Set(v) => Some(v.clone()),
//!                 _ => None,
//!             },
//!             _ => None,
//!         }
//!     }
//!
//!     fn set_string_value(mut self, field_name: &str, value: String) -> Self {
//!         match field_name {
//!             "ssn" => self.ssn = ActiveValue::Set(value),
//!             "credit_card" => self.credit_card = ActiveValue::Set(value),
//!             _ => {}
//!         }
//!         self
//!     }
//! }
//! ```
//!
//! 2. Add helper methods on your Model for convenient encrypted save/find:
//!
//! ```rust,ignore
//! impl users::Model {
//!     /// Save with encryption (use this instead of calling save directly)
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
//!     /// Find by ID and decrypt
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
//!
//!     /// Decrypt fields in place
//!     pub fn decrypt(&mut self, ctx: &AppContext) -> Result<()> {
//!         let provider = ConfigKeyProvider::new(
//!             ctx.config.encryption.clone()
//!                 .ok_or_else(|| Error::string("encryption not configured"))?
//!         )?;
//!         self.decrypt_fields::<users::Entity>(&provider)?;
//!         Ok(())
//!     }
//! }
//! ```
//!
//! 3. Use the helper methods in your controllers:
//!
//! ```rust,ignore
//! // Creating with encryption
//! let user = users::Model::save_encrypted(active_model, &ctx.db, &ctx).await?;
//!
//! // Finding with decryption
//! let user = users::Model::find_decrypt(&ctx.db, 1, &ctx).await?
//!     .ok_or_else(|| Error::NotFound)?;
//! println!("{}", user.ssn); // Decrypted!
//!
//! // Or manually encrypt before save
//! let provider = ConfigKeyProvider::new(ctx.config.encryption.clone().unwrap())?;
//! let encrypted = active_model.encrypt_fields(&provider)?;
//! let user = encrypted.insert(&ctx.db).await?;
//! ```
//!
//! **Note**: SeaORM's `ActiveModelBehavior::before_save` hook does not have access
//! to the `AppContext`, so encryption must be done explicitly before calling save
//! rather than in the hook.

use sea_orm::{ActiveModelTrait, EntityTrait};
use serde::{de::DeserializeOwned, Serialize};

use super::{
    cipher::{decrypt, encrypt},
    errors::{EncryptionError, EncryptionResult},
    format::is_encrypted_format,
    key_provider::KeyProvider,
};

/// Trait for marking a model as having encryptable fields
///
/// Implement this on your `ActiveModel` to specify which fields should be encrypted.
pub trait Encryptable: ActiveModelTrait {
    /// Returns the list of field names that should be encrypted
    ///
    /// These field names must match the column names in the database.
    fn encrypted_fields() -> Vec<String>;

    /// Get the current value of a string field if it is Set
    ///
    /// This method must be implemented for each field that can be encrypted.
    /// Returns `None` if the field is `NotSet` or `Unchanged`.
    fn get_set_string_value(&self, field_name: &str) -> Option<String>;

    /// Set a string field value
    ///
    /// This method must be implemented to set the encrypted value back.
    fn set_string_value(self, field_name: &str, value: String) -> Self
    where
        Self: Sized;

    /// Encrypt all specified fields before saving
    ///
    /// This method should be called in `ActiveModelBehavior::before_save`.
    ///
    /// # Errors
    /// Returns an error if encryption fails
    fn encrypt_fields<P: KeyProvider>(mut self, provider: &P) -> EncryptionResult<Self>
    where
        Self: Sized,
    {
        let fields = Self::encrypted_fields();

        for field_name in &fields {
            // Get the current value for this field
            if let Some(plaintext) = self.get_set_string_value(field_name) {
                // Skip if already encrypted
                if is_encrypted_format(&plaintext) {
                    continue;
                }

                // Get field-specific key (may be derived)
                let key = provider.get_field_key(field_name)?;
                let key_id = provider.get_key_id();

                // Encrypt
                let encrypted = encrypt(&plaintext, &key, key_id)?;

                // Set the encrypted value
                self = self.set_string_value(field_name, encrypted);
            }
        }

        Ok(self)
    }
}

/// Extension trait for decrypting fields on a Model
///
/// This trait provides a generic `decrypt_fields` method that works with any
/// `Model` whose corresponding `ActiveModel` implements `Encryptable`.
pub trait ModelDecryption: Sized + Serialize + DeserializeOwned {
    /// Decrypt all encrypted fields in-place
    ///
    /// This method uses serde_json for runtime field access, converting the
    /// model to JSON, decrypting the relevant fields, and converting back.
    ///
    /// # Type Parameters
    /// * `E` - The Entity type for this model
    /// * `P` - The KeyProvider type
    ///
    /// # Errors
    /// Returns an error if decryption fails
    fn decrypt_fields<E, P>(&mut self, provider: &P) -> EncryptionResult<()>
    where
        E: EntityTrait,
        <E as EntityTrait>::Model: Serialize + DeserializeOwned,
        <E as EntityTrait>::ActiveModel: Encryptable,
        P: KeyProvider,
    {
        let encrypted_fields = <<E as EntityTrait>::ActiveModel as Encryptable>::encrypted_fields();

        // Convert model to JSON for dynamic field access
        let mut value = serde_json::to_value(&self)?;
        let obj = value.as_object_mut().ok_or_else(|| {
            EncryptionError::DecryptionFailed("failed to convert model to JSON object".into())
        })?;

        // Get all decryption keys (for key rotation support)
        let decryption_keys = provider.get_decryption_keys()?;

        // Decrypt each encrypted field
        for field_name in encrypted_fields {
            if let Some(encrypted_json) = obj.get_mut(&field_name) {
                if let Some(encrypted_str) = encrypted_json.as_str() {
                    // Skip if not encrypted
                    if !is_encrypted_format(encrypted_str) {
                        continue;
                    }

                    // Try decrypting with each key until one succeeds
                    let mut decrypted = None;
                    let mut last_error = None;
                    let mut keys_tried = 0;

                    for (key, key_id) in &decryption_keys {
                        keys_tried += 1;
                        // Get field-specific key if derivation is used
                        let field_key = provider.get_field_key(&field_name).unwrap_or(key.clone());

                        match decrypt(encrypted_str, &field_key) {
                            Ok(plaintext) => {
                                decrypted = Some(plaintext);
                                break;
                            }
                            Err(e) => {
                                tracing::debug!(
                                    field = %field_name,
                                    key_id = ?key_id,
                                    error = %e,
                                    "decryption attempt failed, trying next key"
                                );
                                last_error = Some(e);
                            }
                        }
                    }

                    match decrypted {
                        Some(plaintext) => {
                            *encrypted_json = serde_json::Value::String(plaintext);
                        }
                        None => {
                            return Err(if keys_tried == 0 {
                                EncryptionError::field_decryption_failed(
                                    &field_name,
                                    "no keys available for decryption",
                                    None,
                                )
                            } else {
                                EncryptionError::all_keys_failed(
                                    keys_tried,
                                    last_error
                                        .map(|e| e.to_string())
                                        .unwrap_or_else(|| "unknown error".to_string()),
                                )
                            });
                        }
                    }
                }
            }
        }

        // Convert back to Model
        *self = serde_json::from_value(value)?;
        Ok(())
    }
}

// Blanket implementation for all types that implement Serialize + DeserializeOwned
impl<M> ModelDecryption for M where M: Serialize + DeserializeOwned {}

/// Helper function to decrypt a single field value
///
/// Useful when you need to decrypt a field without going through the full
/// `ModelDecryption` trait.
///
/// # Errors
/// Returns an error if decryption fails
pub fn decrypt_field<P: KeyProvider>(
    encrypted_value: &str,
    field_name: &str,
    provider: &P,
) -> EncryptionResult<String> {
    if !is_encrypted_format(encrypted_value) {
        return Ok(encrypted_value.to_string());
    }

    let key = provider.get_field_key(field_name)?;
    decrypt(encrypted_value, &key)
}

/// Helper function to encrypt a single field value
///
/// Useful when you need to encrypt a field without going through the full
/// `Encryptable` trait.
///
/// # Errors
/// Returns an error if encryption fails
pub fn encrypt_field<P: KeyProvider>(
    plaintext: &str,
    field_name: &str,
    provider: &P,
) -> EncryptionResult<String> {
    let key = provider.get_field_key(field_name)?;
    let key_id = provider.get_key_id();
    encrypt(plaintext, &key, key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::key_provider::StaticKeyProvider;

    fn test_provider() -> StaticKeyProvider {
        StaticKeyProvider::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            Some("test".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_field_helpers() {
        let provider = test_provider();
        let plaintext = "secret value";
        let field_name = "ssn";

        let encrypted = encrypt_field(plaintext, field_name, &provider).unwrap();
        assert!(is_encrypted_format(&encrypted));

        let decrypted = decrypt_field(&encrypted, field_name, &provider).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_field_passthrough_plaintext() {
        let provider = test_provider();
        let plaintext = "not encrypted";

        let result = decrypt_field(plaintext, "ssn", &provider).unwrap();
        assert_eq!(result, plaintext);
    }
}
