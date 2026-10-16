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
