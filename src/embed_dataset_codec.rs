use ciborium::value::Value;
use serde::{Deserialize, Serialize};

const VECTOR_TAG: u64 = 81;

/// One source item: admin-supplied raw text + optional payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceItem {
    /// Stable caller-provided item identifier.
    pub id: String,
    /// Raw text to embed.
    pub text: String,
    /// Optional JSON-compatible metadata carried with the source item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// One corpus item: source id + embedding vector + optional payload
/// (carried through from source).
#[derive(Clone, Debug, PartialEq)]
pub struct CorpusItem {
    /// Stable caller-provided item identifier matching the source item.
    pub id: String,
    /// Embedding vector for the item.
    pub vector: Vec<f32>,
    /// Optional JSON-compatible metadata carried through from the source item.
    pub payload: Option<serde_json::Value>,
}

/// Encode a slice of source items as deterministic CBOR per the design-16
/// encoding profile. Result is the bytes stored in the `source_items`
/// content blob.
pub fn encode_source_items(items: &[SourceItem]) -> Result<Vec<u8>, EmbedDatasetCodecError> {
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let mut entries = vec![
            text_entry("id", Value::Text(item.id.clone())),
            text_entry("text", Value::Text(item.text.clone())),
        ];
        if let Some(payload) = &item.payload {
            entries.push((
                Value::Text("payload".to_string()),
                json_to_cbor(payload).map_err(EmbedDatasetCodecError::MalformedSourceItems)?,
            ));
        }
        values.push(sorted_map(entries).map_err(EmbedDatasetCodecError::MalformedSourceItems)?);
    }

    encode_value(&Value::Array(values)).map_err(EmbedDatasetCodecError::MalformedSourceItems)
}

/// Decode the storage bytes of a `source_items` blob.
pub fn decode_source_items(bytes: &[u8]) -> Result<Vec<SourceItem>, EmbedDatasetCodecError> {
    let value = decode_value(bytes)?;
    let items = match value {
        Value::Array(items) => items,
        _ => {
            return Err(EmbedDatasetCodecError::MalformedSourceItems(
                "top-level value must be an array".to_string(),
            ));
        }
    };

    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        let map = expect_map(
            item,
            "source item",
            EmbedDatasetCodecError::MalformedSourceItems,
        )?;
        let id = required_text(&map, "id", EmbedDatasetCodecError::MalformedSourceItems)?;
        let text = required_text(&map, "text", EmbedDatasetCodecError::MalformedSourceItems)?;
        let payload = optional_payload(&map, EmbedDatasetCodecError::MalformedSourceItems)?;
        decoded.push(SourceItem { id, text, payload });
    }

    Ok(decoded)
}

/// Encode a slice of corpus items as deterministic CBOR per the design-16
/// encoding profile, with each `vector` as RFC 8746 tag 81 (IEEE 754 binary32,
/// big endian, Typed Array). Result is the bytes stored in the `corpus`
/// content blob.
pub fn encode_corpus(items: &[CorpusItem]) -> Result<Vec<u8>, EmbedDatasetCodecError> {
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let mut entries = vec![
            text_entry("id", Value::Text(item.id.clone())),
            text_entry("vector", vector_to_cbor(&item.vector)),
        ];
        if let Some(payload) = &item.payload {
            entries.push((
                Value::Text("payload".to_string()),
                json_to_cbor(payload).map_err(EmbedDatasetCodecError::MalformedCorpus)?,
            ));
        }
        values.push(sorted_map(entries).map_err(EmbedDatasetCodecError::MalformedCorpus)?);
    }

    encode_value(&Value::Array(values)).map_err(EmbedDatasetCodecError::MalformedCorpus)
}

/// Decode the storage bytes of a `corpus` blob.
pub fn decode_corpus(bytes: &[u8]) -> Result<Vec<CorpusItem>, EmbedDatasetCodecError> {
    let value = decode_value(bytes)?;
    let items = match value {
        Value::Array(items) => items,
        _ => {
            return Err(EmbedDatasetCodecError::MalformedCorpus(
                "top-level value must be an array".to_string(),
            ));
        }
    };

    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        let map = expect_map(item, "corpus item", EmbedDatasetCodecError::MalformedCorpus)?;
        let id = required_text(&map, "id", EmbedDatasetCodecError::MalformedCorpus)?;
        let vector_value = required_value(&map, "vector", EmbedDatasetCodecError::MalformedCorpus)?;
        let vector = cbor_to_vector(vector_value)?;
        let payload = optional_payload(&map, EmbedDatasetCodecError::MalformedCorpus)?;
        decoded.push(CorpusItem {
            id,
            vector,
            payload,
        });
    }

    Ok(decoded)
}

/// Errors produced while encoding or decoding embedding-dataset blobs.
#[derive(Debug, thiserror::Error)]
pub enum EmbedDatasetCodecError {
    /// Storage bytes are not valid CBOR.
    #[error("invalid CBOR: {0}")]
    InvalidCbor(String),
    /// Storage bytes do not match the expected source-items shape.
    #[error("malformed source-items blob: {0}")]
    MalformedSourceItems(String),
    /// Storage bytes do not match the expected corpus shape.
    #[error("malformed corpus blob: {0}")]
    MalformedCorpus(String),
    /// A vector tag has an unexpected payload length.
    #[error("malformed RFC 8746 tag 81 payload: {0}")]
    MalformedVectorTag(String),
}

fn decode_value(bytes: &[u8]) -> Result<Value, EmbedDatasetCodecError> {
    ciborium::de::from_reader(bytes)
        .map_err(|err| EmbedDatasetCodecError::InvalidCbor(err.to_string()))
}

fn encode_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|err| err.to_string())?;
    Ok(out)
}

fn text_entry(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.to_string()), value)
}

fn sorted_map(entries: Vec<(Value, Value)>) -> Result<Value, String> {
    let mut keyed = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = deterministic_value(key)?;
        let value = deterministic_value(value)?;
        let key_bytes = encode_value(&key)?;
        keyed.push((key_bytes, key, value));
    }

    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        keyed
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

fn deterministic_value(value: Value) -> Result<Value, String> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(deterministic_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Map(entries) => sorted_map(entries),
        Value::Float(float) if float.is_finite() => Ok(Value::Float(float)),
        Value::Float(_) => Err("floating-point values must be finite".to_string()),
        other => Ok(other),
    }
}

fn json_to_cbor(value: &serde_json::Value) -> Result<Value, String> {
    match value {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Bool(value) => Ok(Value::Bool(*value)),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Ok(Value::Integer(value.into()))
            } else if let Some(value) = number.as_u64() {
                Ok(Value::Integer(value.into()))
            } else if let Some(value) = number.as_f64() {
                if value.is_finite() {
                    Ok(Value::Float(value))
                } else {
                    Err("JSON number must be finite".to_string())
                }
            } else {
                Err("JSON number is outside the supported CBOR range".to_string())
            }
        }
        serde_json::Value::String(value) => Ok(Value::Text(value.clone())),
        serde_json::Value::Array(items) => items
            .iter()
            .map(json_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        serde_json::Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (key, value) in map {
                entries.push((Value::Text(key.clone()), json_to_cbor(value)?));
            }
            sorted_map(entries)
        }
    }
}

fn cbor_to_json(value: &Value) -> Result<serde_json::Value, String> {
    match value {
        Value::Null => Ok(serde_json::Value::Null),
        Value::Bool(value) => Ok(serde_json::Value::Bool(*value)),
        Value::Integer(value) => {
            let value = i128::from(*value);
            if let Ok(value) = i64::try_from(value) {
                Ok(serde_json::Value::Number(value.into()))
            } else if let Ok(value) = u64::try_from(value) {
                Ok(serde_json::Value::Number(value.into()))
            } else {
                Err("integer is outside JSON number range".to_string())
            }
        }
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "floating-point value must be finite".to_string()),
        Value::Text(value) => Ok(serde_json::Value::String(value.clone())),
        Value::Array(items) => items
            .iter()
            .map(cbor_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, value) in entries {
                let key = match key {
                    Value::Text(key) => key.clone(),
                    _ => return Err("payload map keys must be strings".to_string()),
                };
                map.insert(key, cbor_to_json(value)?);
            }
            Ok(serde_json::Value::Object(map))
        }
        Value::Bytes(_) | Value::Tag(_, _) => Err("value is not JSON-compatible".to_string()),
        _ => Err("unsupported CBOR value".to_string()),
    }
}

fn vector_to_cbor(vector: &[f32]) -> Value {
    let mut bytes = Vec::with_capacity(vector.len().saturating_mul(4));
    for value in vector {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Value::Tag(VECTOR_TAG, Box::new(Value::Bytes(bytes)))
}

fn cbor_to_vector(value: &Value) -> Result<Vec<f32>, EmbedDatasetCodecError> {
    let bytes = match value {
        Value::Tag(VECTOR_TAG, tagged) => match tagged.as_ref() {
            Value::Bytes(bytes) => bytes,
            _ => {
                return Err(EmbedDatasetCodecError::MalformedCorpus(
                    "vector tag payload must be a byte string".to_string(),
                ));
            }
        },
        _ => {
            return Err(EmbedDatasetCodecError::MalformedCorpus(
                "vector must be RFC 8746 tag 81".to_string(),
            ));
        }
    };

    let chunks = bytes.chunks_exact(4);
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        return Err(EmbedDatasetCodecError::MalformedVectorTag(format!(
            "byte length {} is not a multiple of 4",
            bytes.len()
        )));
    }

    let mut vector = Vec::with_capacity(bytes.len() / 4);
    for chunk in chunks {
        let chunk_bytes = <[u8; 4]>::try_from(chunk).map_err(|_| {
            EmbedDatasetCodecError::MalformedVectorTag(
                "internal vector chunk length mismatch".to_string(),
            )
        })?;
        vector.push(f32::from_be_bytes(chunk_bytes));
    }
    Ok(vector)
}

fn expect_map(
    value: Value,
    label: &str,
    error: fn(String) -> EmbedDatasetCodecError,
) -> Result<Vec<(Value, Value)>, EmbedDatasetCodecError> {
    match value {
        Value::Map(map) => Ok(map),
        _ => Err(error(format!("{label} must be a map"))),
    }
}

fn required_value<'a>(
    map: &'a [(Value, Value)],
    key: &'static str,
    error: fn(String) -> EmbedDatasetCodecError,
) -> Result<&'a Value, EmbedDatasetCodecError> {
    let key_value = Value::Text(key.to_string());
    map.iter()
        .find(|(candidate, _)| candidate == &key_value)
        .map(|(_, value)| value)
        .ok_or_else(|| error(format!("missing required key '{key}'")))
}

fn required_text(
    map: &[(Value, Value)],
    key: &'static str,
    error: fn(String) -> EmbedDatasetCodecError,
) -> Result<String, EmbedDatasetCodecError> {
    match required_value(map, key, error)? {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(error(format!("key '{key}' must be a text string"))),
    }
}

fn optional_payload(
    map: &[(Value, Value)],
    error: fn(String) -> EmbedDatasetCodecError,
) -> Result<Option<serde_json::Value>, EmbedDatasetCodecError> {
    let key_value = Value::Text("payload".to_string());
    match map.iter().find(|(candidate, _)| candidate == &key_value) {
        Some((_, value)) => cbor_to_json(value).map(Some).map_err(error),
        None => Ok(None),
    }
}
