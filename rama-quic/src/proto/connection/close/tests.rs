use crate::proto::connection::close::CloseResponses;

#[test]
fn each_close_response_costs_twice_the_last() {
    // From a fresh counter, with an answer taken every time one is earned. The connection
    // arms its first close itself, so its own sequence starts one answer further on; that
    // is asserted at the connection level.
    let mut responses = CloseResponses::new();
    let mut earned_at = Vec::new();
    for input in 1..=16u32 {
        if responses.arrived() {
            earned_at.push(input);
            responses.answered();
        }
    }
    assert_eq!(earned_at, vec![1, 3, 7, 15]);
}

#[test]
fn the_gap_between_close_responses_saturates() {
    let mut responses = CloseResponses::new();
    for _ in 0..64 {
        responses.answered();
    }
    assert_eq!(
        responses.gap.get(),
        u32::MAX,
        "it stops rather than wrapping"
    );
    // The count towards it saturates too, so a long run of input cannot wrap into an answer
    // it did not earn.
    responses.seen = u32::MAX - 2;
    assert!(!responses.arrived(), "one short of the gap is still short");
    assert!(responses.arrived(), "and the next one meets it exactly");
    assert_eq!(responses.seen, 0, "which starts the count again");
}
