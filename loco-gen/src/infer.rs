use cruet::{case::snake::to_snake_case, Inflector};

use crate::{Error, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum MigrationType {
    CreateTable { table: String },
    AddColumns { table: String },
    RemoveColumns { table: String },
    AddReference { table: String },
    CreateJoinTable { table_a: String, table_b: String },
    Empty,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptionMode {
    NonDeterministic,
    Deterministic,
}

pub enum FieldType {
    Reference,
    ReferenceWithCustomField(String),
    NullableReference,
    NullableReferenceWithCustomField(String),
    Type(String),
    TypeWithParameters(String, Vec<String>),
    /// A column whose Rust-level value is encrypted before persistence.
    ///
    /// The DB column is still typed by the inner type (e.g. `string`,
    /// `text`); only the in-row value is wrapped in the Loco encryption
    /// envelope. References cannot be encrypted.
    Encrypted {
        inner: Box<FieldType>,
        mode: EncryptionMode,
    },
}

pub fn parse_field_type(ftype: &str) -> Result<FieldType> {
    let parts: Vec<&str> = ftype.split(':').collect();

    // Peel off a trailing `:encrypted` or `:encrypted:deterministic` modifier
    // so it can be recognized regardless of the underlying column type.
    let (base, encryption) = match parts.as_slice() {
        [.., "encrypted", "deterministic"] => (
            &parts[..parts.len() - 2],
            Some(EncryptionMode::Deterministic),
        ),
        [.., "encrypted"] => (
            &parts[..parts.len() - 1],
            Some(EncryptionMode::NonDeterministic),
        ),
        _ => (&parts[..], None),
    };

    let inner = match base {
        ["references?"] => FieldType::NullableReference,
        ["references?", f] => FieldType::NullableReferenceWithCustomField((*f).to_string()),
        ["references"] => FieldType::Reference,
        ["references", f] => FieldType::ReferenceWithCustomField((*f).to_string()),
        [t] => FieldType::Type((*t).to_string()),
        [t, params @ ..] => FieldType::TypeWithParameters(
            (*t).to_string(),
            params.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ),
        [] => return Err(Error::Message(format!("cannot parse type: `{ftype}`"))),
    };

    match encryption {
        None => Ok(inner),
        Some(mode) => match inner {
            FieldType::Reference
            | FieldType::ReferenceWithCustomField(_)
            | FieldType::NullableReference
            | FieldType::NullableReferenceWithCustomField(_) => Err(Error::Message(format!(
                "cannot encrypt a reference field: `{ftype}` (encryption applies to values, not \
                 foreign keys)"
            ))),
            other => Ok(FieldType::Encrypted {
                inner: Box::new(other),
                mode,
            }),
        },
    }
}
pub fn guess_migration_type(migration_name: &str) -> MigrationType {
    let normalized_name = to_snake_case(migration_name);
    let parts: Vec<&str> = normalized_name.split('_').collect();

    match parts.as_slice() {
        ["create", table_name] => MigrationType::CreateTable {
            table: table_name.to_plural(),
        },
        ["add", _reference_name, "ref", "to", table_name] => MigrationType::AddReference {
            table: table_name.to_plural(),
        },
        ["add", _column_names @ .., "to", table_name] => MigrationType::AddColumns {
            table: table_name.to_plural(),
        },
        ["remove", _column_names @ .., "from", table_name] => MigrationType::RemoveColumns {
            table: table_name.to_plural(),
        },
        ["create", "join", "table", parts @ ..] => parts
            .iter()
            .position(|&part| part == "and")
            .map_or(MigrationType::Empty, |and_index| {
                let first_parts = &parts[..and_index];
                let second_parts = &parts[and_index + 1..];

                if first_parts.is_empty() || second_parts.is_empty() {
                    return MigrationType::Empty;
                }

                let table_a = first_parts.join("_");
                let table_b = second_parts.join("_");

                let table_a = table_a.to_singular();
                let table_b = table_b.to_singular();
                MigrationType::CreateJoinTable { table_a, table_b }
            }),
        _ => MigrationType::Empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_create_table() {
        assert_eq!(
            guess_migration_type("CreateUsers"),
            MigrationType::CreateTable {
                table: "users".to_string(),
            }
        );
    }

    #[test]
    fn test_infer_add_columns() {
        assert_eq!(
            guess_migration_type("AddNameAndAgeToUsers"),
            MigrationType::AddColumns {
                table: "users".to_string(),
            }
        );
    }

    #[test]
    fn test_infer_remove_columns() {
        assert_eq!(
            guess_migration_type("RemoveNameAndAgeFromUsers"),
            MigrationType::RemoveColumns {
                table: "users".to_string(),
            }
        );
    }

    #[test]
    fn test_infer_add_reference() {
        assert_eq!(
            guess_migration_type("AddUserRefToPosts"),
            MigrationType::AddReference {
                table: "posts".to_string(),
            }
        );
    }

    #[test]
    fn test_infer_create_join_table() {
        assert_eq!(
            guess_migration_type("CreateJoinTableUsersAndGroups"),
            MigrationType::CreateJoinTable {
                table_a: "user".to_string(),
                table_b: "group".to_string()
            }
        );
    }

    #[test]
    fn test_infer_create_join_table_with_underscores() {
        // Test the specific case that was failing
        assert_eq!(
            guess_migration_type("CreateJoinTableGlobal_recipesAndGlobal_materials"),
            MigrationType::CreateJoinTable {
                table_a: "global_recipe".to_string(),
                table_b: "global_material".to_string()
            }
        );
    }

    #[test]
    fn test_infer_create_join_table_complex_names() {
        // Test more complex table names with multiple underscores
        assert_eq!(
            guess_migration_type("CreateJoinTableUser_profilesAndGroup_members"),
            MigrationType::CreateJoinTable {
                table_a: "user_profile".to_string(),
                table_b: "group_member".to_string()
            }
        );
    }

    #[test]
    fn test_infer_create_join_table_mixed_names() {
        // Test one simple name and one complex name
        assert_eq!(
            guess_migration_type("CreateJoinTableUsersAndGroup_members"),
            MigrationType::CreateJoinTable {
                table_a: "user".to_string(),
                table_b: "group_member".to_string()
            }
        );
    }

    #[test]
    fn test_empty_migration() {
        assert_eq!(
            guess_migration_type("UnknownMigrationType"),
            MigrationType::Empty
        );
    }

    #[test]
    fn test_infer_create_join_table_no_and_separator() {
        // Test case where there's no "and" separator
        assert_eq!(
            guess_migration_type("CreateJoinTableUsersGroups"),
            MigrationType::Empty
        );
    }

    #[test]
    fn test_infer_create_join_table_empty_after_and() {
        // Test case where there are no parts after "and"
        assert_eq!(
            guess_migration_type("CreateJoinTableUsersAnd"),
            MigrationType::Empty
        );
    }

    #[test]
    fn test_infer_create_join_table_empty_before_and() {
        // Test case where there are no parts before "and"
        assert_eq!(
            guess_migration_type("CreateJoinTableAndGroups"),
            MigrationType::Empty
        );
    }

    #[test]
    fn test_infer_create_join_table_multiple_ands() {
        // Test case with multiple "and" separators (should use first one)
        assert_eq!(
            guess_migration_type("CreateJoinTableUsersAndGroupsAndMore"),
            MigrationType::CreateJoinTable {
                table_a: "user".to_string(),
                table_b: "groups_and_more".to_string()
            }
        );
    }
}
