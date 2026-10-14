use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_STRING_LENGTH: usize = 256;
const MAX_STRUCT_FIELDS: usize = 16;

/// The value contract for one probe execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReturnSchema {
    Bool,
    Number,
    String {
        /// Maximum UTF-8 byte length of the returned string.
        max_len: usize,
    },
    Struct {
        fields: BTreeMap<String, ScalarSchema>,
    },
}

/// A non-nested field in a [`ReturnSchema::Struct`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScalarSchema {
    Bool,
    Number,
    String {
        /// Maximum UTF-8 byte length of the returned field.
        max_len: usize,
    },
}

/// A probe result after validation against its declared schema.
#[derive(Clone, Debug, PartialEq)]
pub enum ProbeValue {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Struct(BTreeMap<String, ScalarValue>),
}

/// A validated scalar field in a structured result.
#[derive(Clone, Debug, PartialEq)]
pub enum ScalarValue {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReturnSchemaError {
    InvalidFieldName,
    StringLimitTooLarge { path: String, max_len: usize },
    TooManyFields { count: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReturnValidationError {
    TypeMismatch {
        path: String,
        expected: &'static str,
        actual: &'static str,
    },
    StringTooLong {
        path: String,
        max_len: usize,
        actual_len: usize,
    },
    MissingField {
        field: String,
    },
    UnexpectedField {
        field: String,
    },
    /// The encoded return value did not fit the guest's bounded response.
    /// Every legal value is far smaller (strings are capped at 256 bytes and
    /// structs at 16 scalar fields), so this names a probe that returned
    /// something its schema could never accept, rather than leaving it to
    /// surface as an unreadable sandbox failure.
    TooLarge {
        bytes: usize,
        limit: usize,
    },
}

impl ReturnSchema {
    /// Check a DECLARED schema against the closed grammar.
    ///
    /// Public because registration must reject a bad declaration at the moment
    /// an operator can fix it, and the alternative — re-encoding the same caps
    /// in the caller — is two sources of truth for one grammar. They would drift
    /// silently: the caller would accept a schema this crate later rejects, and
    /// the mismatch would surface as a poll-time validation failure rather than
    /// a refused registration.
    pub fn validate_declaration(&self) -> Result<(), ReturnSchemaError> {
        match self {
            Self::Bool | Self::Number => Ok(()),
            Self::String { max_len } => validate_string_limit("$", *max_len),
            Self::Struct { fields } => {
                if fields.len() > MAX_STRUCT_FIELDS {
                    return Err(ReturnSchemaError::TooManyFields {
                        count: fields.len(),
                    });
                }
                for (name, schema) in fields {
                    if name.is_empty() || name.len() > MAX_STRING_LENGTH {
                        return Err(ReturnSchemaError::InvalidFieldName);
                    }
                    if let ScalarSchema::String { max_len } = schema {
                        validate_string_limit(&format!("$.{name}"), *max_len)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub(crate) fn validate_value(&self, value: Value) -> Result<ProbeValue, ReturnValidationError> {
        match self {
            Self::Bool => value
                .as_bool()
                .map(ProbeValue::Bool)
                .ok_or_else(|| type_mismatch("$", "bool", &value)),
            Self::Number => match value {
                Value::Number(number) => Ok(ProbeValue::Number(number)),
                other => Err(type_mismatch("$", "number", &other)),
            },
            Self::String { max_len } => match value {
                Value::String(string) => {
                    validate_string_value("$", string, *max_len).map(ProbeValue::String)
                }
                other => Err(type_mismatch("$", "string", &other)),
            },
            Self::Struct { fields } => {
                let Value::Object(mut object) = value else {
                    return Err(type_mismatch("$", "struct", &value));
                };
                for field in object.keys() {
                    if !fields.contains_key(field) {
                        return Err(ReturnValidationError::UnexpectedField {
                            field: field_preview(field),
                        });
                    }
                }
                let mut validated = BTreeMap::new();
                for (name, schema) in fields {
                    let value =
                        object
                            .remove(name)
                            .ok_or_else(|| ReturnValidationError::MissingField {
                                field: name.clone(),
                            })?;
                    validated.insert(
                        name.clone(),
                        schema.validate_value(&format!("$.{name}"), value)?,
                    );
                }
                Ok(ProbeValue::Struct(validated))
            }
        }
    }
}

impl ScalarSchema {
    fn validate_value(
        &self,
        path: &str,
        value: Value,
    ) -> Result<ScalarValue, ReturnValidationError> {
        match self {
            Self::Bool => value
                .as_bool()
                .map(ScalarValue::Bool)
                .ok_or_else(|| type_mismatch(path, "bool", &value)),
            Self::Number => match value {
                Value::Number(number) => Ok(ScalarValue::Number(number)),
                other => Err(type_mismatch(path, "number", &other)),
            },
            Self::String { max_len } => match value {
                Value::String(string) => {
                    validate_string_value(path, string, *max_len).map(ScalarValue::String)
                }
                other => Err(type_mismatch(path, "string", &other)),
            },
        }
    }
}

fn validate_string_limit(path: &str, max_len: usize) -> Result<(), ReturnSchemaError> {
    if max_len <= MAX_STRING_LENGTH {
        Ok(())
    } else {
        Err(ReturnSchemaError::StringLimitTooLarge {
            path: path.to_owned(),
            max_len,
        })
    }
}

fn validate_string_value(
    path: &str,
    string: String,
    max_len: usize,
) -> Result<String, ReturnValidationError> {
    let actual_len = string.len();
    if actual_len <= max_len {
        Ok(string)
    } else {
        Err(ReturnValidationError::StringTooLong {
            path: path.to_owned(),
            max_len,
            actual_len,
        })
    }
}

fn type_mismatch(path: &str, expected: &'static str, actual: &Value) -> ReturnValidationError {
    ReturnValidationError::TypeMismatch {
        path: path.to_owned(),
        expected,
        actual: value_kind(actual),
    }
}

fn field_preview(field: &str) -> String {
    let mut characters = field.chars();
    let mut preview: String = characters.by_ref().take(64).collect();
    if characters.next().is_some() {
        preview.push('…');
    }
    preview
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "struct",
    }
}

impl fmt::Display for ReturnSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldName => write!(
                f,
                "struct field names must have 1..={MAX_STRING_LENGTH} UTF-8 bytes"
            ),
            Self::StringLimitTooLarge { path, max_len } => {
                write!(
                    f,
                    "string limit at {path} is {max_len}; maximum is {MAX_STRING_LENGTH}"
                )
            }
            Self::TooManyFields { count } => {
                write!(
                    f,
                    "struct has {count} fields; maximum is {MAX_STRUCT_FIELDS}"
                )
            }
        }
    }
}

impl std::error::Error for ReturnSchemaError {}

#[test]
fn struct_field_names_and_diagnostics_are_bounded() {
    for name in [String::new(), "x".repeat(MAX_STRING_LENGTH + 1)] {
        let schema = ReturnSchema::Struct {
            fields: BTreeMap::from([(name, ScalarSchema::Bool)]),
        };
        assert!(
            schema.validate_declaration().is_err(),
            "struct field names must be bounded and nonempty"
        );
    }
    let schema = ReturnSchema::Struct {
        fields: BTreeMap::new(),
    };
    let error = schema
        .validate_value(serde_json::json!({"x".repeat(60_000):true}))
        .unwrap_err();
    assert!(
        error.to_string().len() < 256,
        "unexpected-field diagnostics must be bounded"
    );
}

impl fmt::Display for ReturnValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch {
                path,
                expected,
                actual,
            } => write!(f, "return value at {path} must be {expected}, not {actual}"),
            Self::StringTooLong {
                path,
                max_len,
                actual_len,
            } => write!(
                f,
                "return string at {path} is {actual_len} bytes; maximum is {max_len}"
            ),
            Self::MissingField { field } => write!(f, "return struct is missing field {field}"),
            Self::UnexpectedField { field } => {
                write!(f, "return struct has undeclared field {field}")
            }
            Self::TooLarge { bytes, limit } => write!(
                f,
                "return value encodes to {bytes} bytes; the probe response limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for ReturnValidationError {}
