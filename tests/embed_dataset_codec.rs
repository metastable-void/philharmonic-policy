use ciborium::value::Value;
use hex_literal::hex;
use philharmonic_policy::{
    CorpusItem, EmbedDatasetCodecError, SourceItem, decode_corpus, decode_source_items,
    encode_corpus, encode_source_items,
};
use serde_json::json;

#[test]
fn source_items_round_trip_deterministically() {
    let items = source_items_fixture();

    let first = encode_source_items(&items).unwrap();
    let second = encode_source_items(&items).unwrap();

    assert_eq!(first, second);
    assert_eq!(decode_source_items(&first).unwrap(), items);
}

#[test]
fn corpus_round_trip_deterministically() {
    let items = vec![
        CorpusItem {
            id: "one".to_string(),
            vector: vec![1.25],
            payload: None,
        },
        CorpusItem {
            id: "wide-1024".to_string(),
            vector: (0..1024).map(|value| value as f32 / 10.0).collect(),
            payload: Some(json!({"kind": "medium", "rank": 2})),
        },
        CorpusItem {
            id: "wide-4096".to_string(),
            vector: (0..4096).map(|value| -(value as f32)).collect(),
            payload: Some(json!({"nested": {"ok": true}})),
        },
    ];

    let first = encode_corpus(&items).unwrap();
    let second = encode_corpus(&items).unwrap();
    let decoded = decode_corpus(&first).unwrap();

    assert_eq!(first, second);
    assert_eq!(decoded.len(), items.len());
    for (actual, expected) in decoded.iter().zip(items.iter()) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(
            actual
                .vector
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected
                .vector
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn source_items_known_vectors() {
    // Expected bytes were generated once with encode_source_items on
    // 2026-05-10, inspected as hex, then committed here to catch drift.
    let vector_1 = vec![SourceItem {
        id: "a".to_string(),
        text: "alpha".to_string(),
        payload: None,
    }];
    let expected_1 = hex!("81a26269646161647465787465616c706861");

    let vector_2 = source_items_fixture();
    let expected_2 = hex!(
        "82a362696465666972737464746578746b68656c6c6f20776f726c64677061796c6f6164a36161a2636e696cf6666e6573746564f5617a83030201646e616d65676578616d706c65a3626964667365636f6e64647465787467676f6f64627965677061796c6f6164a364666c6167f465636f756e74182a656974656d738261786179"
    );

    assert_eq!(encode_source_items(&vector_1).unwrap(), expected_1);
    assert_eq!(encode_source_items(&vector_2).unwrap(), expected_2);
}

#[test]
fn corpus_known_vectors() {
    // Expected bytes were generated once with encode_corpus on 2026-05-10,
    // inspected as hex, then committed here to catch drift.
    let vector_1 = vec![CorpusItem {
        id: "triple".to_string(),
        vector: vec![1.0, 2.0, 3.0],
        payload: None,
    }];
    let expected_1 = hex!("81a262696466747269706c6566766563746f72d8514c3f8000004000000040400000");

    let vector_2 = vec![CorpusItem {
        id: "with-payload".to_string(),
        vector: vec![-1.5, 0.0],
        payload: Some(json!({"label": "signed", "enabled": true})),
    }];
    let expected_2 = hex!(
        "81a36269646c776974682d7061796c6f616466766563746f72d85148bfc0000000000000677061796c6f6164a2656c6162656c667369676e656467656e61626c6564f5"
    );

    assert_eq!(encode_corpus(&vector_1).unwrap(), expected_1);
    assert_eq!(encode_corpus(&vector_2).unwrap(), expected_2);
}

#[test]
fn corpus_vector_uses_tag_81_big_endian_binary32_layout() {
    let encoded = encode_corpus(&[CorpusItem {
        id: "one".to_string(),
        vector: vec![1.0],
        payload: None,
    }])
    .unwrap();

    let value: Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    let vector_bytes = find_first_tag_81_bytes(&value).unwrap();

    assert_eq!(vector_bytes, &[0x3f, 0x80, 0x00, 0x00]);
}

#[test]
fn malformed_input_is_rejected() {
    assert!(matches!(
        decode_source_items(&[0x81, 0xa2, 0x62]),
        Err(EmbedDatasetCodecError::InvalidCbor(_))
    ));

    let bad_vector = Value::Array(vec![Value::Map(vec![
        (
            Value::Text("id".to_string()),
            Value::Text("bad".to_string()),
        ),
        (
            Value::Text("vector".to_string()),
            Value::Tag(81, Box::new(Value::Bytes(vec![0, 1, 2, 3, 4]))),
        ),
    ])]);
    let mut bad_vector_bytes = Vec::new();
    ciborium::ser::into_writer(&bad_vector, &mut bad_vector_bytes).unwrap();
    assert!(matches!(
        decode_corpus(&bad_vector_bytes),
        Err(EmbedDatasetCodecError::MalformedVectorTag(_))
    ));

    let missing_id = hex!("81a164746578746568656c6c6f");
    assert!(matches!(
        decode_source_items(&missing_id),
        Err(EmbedDatasetCodecError::MalformedSourceItems(_))
    ));

    let missing_corpus_id = Value::Array(vec![Value::Map(vec![(
        Value::Text("vector".to_string()),
        Value::Tag(81, Box::new(Value::Bytes(vec![0, 0, 0, 0]))),
    )])]);
    let mut missing_corpus_id_bytes = Vec::new();
    ciborium::ser::into_writer(&missing_corpus_id, &mut missing_corpus_id_bytes).unwrap();
    assert!(matches!(
        decode_corpus(&missing_corpus_id_bytes),
        Err(EmbedDatasetCodecError::MalformedCorpus(_))
    ));
}

#[test]
fn payload_round_trips_and_absent_payload_stays_absent() {
    let items = vec![
        SourceItem {
            id: "with".to_string(),
            text: "has payload".to_string(),
            payload: Some(json!({"a": 1, "b": [true, null, "x"]})),
        },
        SourceItem {
            id: "without".to_string(),
            text: "no payload".to_string(),
            payload: None,
        },
    ];

    let decoded = decode_source_items(&encode_source_items(&items).unwrap()).unwrap();

    assert_eq!(decoded, items);
    assert!(decoded[1].payload.is_none());
}

fn source_items_fixture() -> Vec<SourceItem> {
    vec![
        SourceItem {
            id: "first".to_string(),
            text: "hello world".to_string(),
            payload: Some(json!({
                "z": [3, 2, 1],
                "a": {"nested": true, "nil": null},
                "name": "example"
            })),
        },
        SourceItem {
            id: "second".to_string(),
            text: "goodbye".to_string(),
            payload: Some(json!({
                "count": 42,
                "flag": false,
                "items": ["x", "y"]
            })),
        },
    ]
}

fn find_first_tag_81_bytes(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Tag(81, tagged) => match tagged.as_ref() {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        },
        Value::Array(items) => items.iter().find_map(find_first_tag_81_bytes),
        Value::Map(entries) => entries.iter().find_map(|(key, value)| {
            find_first_tag_81_bytes(key).or_else(|| find_first_tag_81_bytes(value))
        }),
        _ => None,
    }
}
