use super::*;
use serde_json::{Value, json};

fn flight() -> RecordedInitialFlight {
    let packets = (0..2)
        .map(|index| {
            InitialPacket::try_new(
                index + 1,
                1 + index as u8,
                1250,
                0,
                vec![
                    InitialFrame::Crypto {
                        offset: index * 100,
                        len: 100,
                    },
                    InitialFrame::Ping,
                    InitialFrame::Padding { len: 1000 },
                ],
            )
            .unwrap()
        })
        .collect();
    RecordedInitialFlight::try_new(Version::V1, 8, 0, packets).unwrap()
}

#[test]
fn decoded_layout_keeps_the_original_schedule_and_bounded_crypto_extent() {
    let source = flight();
    let decoded: RecordedInitialFlight =
        serde_json::from_slice(&serde_json::to_vec(&source).unwrap()).unwrap();
    assert_eq!(decoded, source);
    assert_eq!(decoded.crypto_len(), 200);
    assert!(decoded.packet(0).is_none());
    assert!(decoded.packet(3).is_none());
    assert_eq!(decoded.packet(1).unwrap().number_len(), 1);
    assert_eq!(decoded.packet(2).unwrap().number_len(), 2);
}

#[test]
fn decoded_layout_rejects_gaps_overlaps_and_conflicting_packet_geometry() {
    let original = serde_json::to_value(flight()).unwrap();
    for case in 0..9 {
        let mut value = original.clone();
        match case {
            0 => value["packets"][1]["frames"][0]["Crypto"]["offset"] = json!(99),
            1 => value["packets"][1]["frames"][0]["Crypto"]["offset"] = json!(101),
            2 => value["packets"][1]["number"] = json!(1),
            3 => value["packets"][1]["number"] = json!(3),
            4 => value["packets"][1]["number_len"] = json!(0),
            5 => value["packets"][1]["datagram_size"] = json!(1251),
            6 => value["source_cid_len"] = json!(21),
            7 => value["destination_cid_len"] = json!(7),
            _ => value["packets"][0]["frames"][0]["Crypto"]["len"] = json!(0),
        }
        serde_json::from_value::<RecordedInitialFlight>(value).unwrap_err();
    }
}

#[test]
fn decoding_budgets_reject_otherwise_contiguous_packet_and_frame_sequences() {
    let mut value = serde_json::to_value(flight()).unwrap();
    let template = value["packets"][0].clone();
    value["packets"] = Value::Array(
        (0..=MAX_PACKETS)
            .map(|index| {
                let mut packet = template.clone();
                packet["number"] = json!(index + 1);
                packet["frames"][0]["Crypto"]["offset"] = json!(index * 100);
                packet
            })
            .collect(),
    );
    serde_json::from_value::<RecordedInitialFlight>(value).unwrap_err();

    let mut packet = template;
    packet["frames"] = Value::Array(
        (0..=MAX_FRAMES)
            .map(|offset| json!({ "Crypto": { "offset": offset, "len": 1 } }))
            .collect(),
    );
    serde_json::from_value::<InitialPacket>(packet).unwrap_err();
}

#[test]
fn standalone_packet_decoding_cannot_bypass_geometry_validation() {
    let original = serde_json::to_value(flight().packets()[0].clone()).unwrap();
    for case in 0..4 {
        let mut value = original.clone();
        match case {
            0 => value["number"] = json!(1u64 << 31),
            1 => value["number_len"] = json!(5),
            2 => value["datagram_size"] = json!(1199),
            _ => value["frames"][0]["Crypto"]["len"] = json!(u64::MAX),
        }
        serde_json::from_value::<InitialPacket>(value).unwrap_err();
    }
}

#[test]
fn decoded_tails_are_bounded_by_the_packet_and_datagram_geometry() {
    let mut value = serde_json::to_value(flight()).unwrap();
    value["packets"][0]["trailing_bytes"] = json!(31);
    let decoded: RecordedInitialFlight = serde_json::from_value(value.clone()).unwrap();
    let packet = &decoded.packets()[0];
    assert_eq!(packet.datagram_size(), 1250);
    assert_eq!(packet.packet_size(), 1219);
    assert_eq!(packet.trailing_bytes(), 31);
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);

    for tail in [1250, 1251, 65535, 1000] {
        let mut invalid = value.clone();
        invalid["packets"][0]["trailing_bytes"] = json!(tail);
        serde_json::from_value::<RecordedInitialFlight>(invalid).unwrap_err();
    }
}
