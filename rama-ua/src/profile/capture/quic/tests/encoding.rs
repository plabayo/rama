use super::*;

#[test]
fn flight_import_rejects_noncanonical_runs_and_padding_placement() {
    let limits = QuicFlightCaptureLimits::default();
    for case in 0..9 {
        let mut captured = capture();
        match case {
            0 => captured.flight.frames[0].push(ObservedFrame::Padding { len: 1 }),
            1 => {
                captured.flight.padding = PaddingPlacement::DatagramTail;
                captured.flight.trailing_bytes[0] = captured.flight.datagram_sizes[0];
            }
            2 => captured.flight.padding = PaddingPlacement::DatagramTail,
            3 => captured.flight.trailing_bytes[0] = 1,
            4 => captured.flight.frames[0].clear(),
            case => {
                captured.flight.frames[0][0] = ObservedFrame::Other {
                    ty: [0, 1, 2, 6][case - 5],
                }
            }
        }
        captured.canonical(limits).unwrap_err();
    }
    let mut captured = capture();
    captured.flight.padding = PaddingPlacement::DatagramTail;
    captured.flight.trailing_bytes[0] = 1;
    let value = captured.canonical(limits).unwrap();
    QuicFlightCapture::from_canonical(&value, limits).unwrap();
}

#[test]
fn packet_number_widths_survive_capture_and_structure_without_inference() {
    let mut captured = capture();
    captured.flight.datagram_sizes = vec![1200, 1200];
    captured.flight.trailing_bytes = vec![0, 0];
    captured.flight.packet_number_len = 1;
    captured.flight.packet_numbers = vec![3, 4];
    captured.flight.packet_number_lengths = vec![1, 2];
    captured
        .flight
        .frames
        .push(captured.flight.frames[0].clone());
    let limits = QuicFlightCaptureLimits::default();
    let literal = captured.canonical(limits).unwrap();
    let decoded = QuicFlightCapture::from_canonical(&literal, limits).unwrap();
    assert_eq!(decoded.flight.packet_number_lengths, [1, 2]);
    let structure = captured.structural(limits).unwrap();
    QuicFlightCapture::validate_structure(&structure, limits).unwrap();
    captured.flight.packet_number_lengths[1] = 1;
    assert_ne!(captured.structural(limits).unwrap().id, structure.id);

    for widths in [vec![], vec![1], vec![1, 0], vec![1, 5], vec![2, 2]] {
        captured.flight.packet_number_lengths = widths;
        captured.canonical(limits).unwrap_err();
    }
}
