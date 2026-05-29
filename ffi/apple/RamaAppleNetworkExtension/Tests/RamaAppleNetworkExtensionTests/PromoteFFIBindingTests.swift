import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Swift-side FFI binding tests for the
/// `register_promote_callbacks` / `confirm_promoted` round-trip.
///
/// These cover the bridge layer in `RamaFFI.swift`: callback box
/// lifetimes (no leak, no UAF on session deinit), idempotent
/// replacement, no-op semantics after cancel, and the UTF-8 reason
/// marshalling on `confirmPromoted(.failed, reason:)`.
///
/// Rust-side cutover semantics (callback fires when the in-Rust
/// service calls `into_passthrough`, ACK propagates to the awaiting
/// future, etc.) are covered exhaustively by the Rust engine tests
/// in `src/tproxy/engine/tests/promote.rs`. This file is the Swift
/// boundary's own test surface.
final class PromoteFFIBindingTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let h = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return h
    }

    private func tcpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func newInterceptedTcpSession(
        on engine: RamaTransparentProxyEngineHandle
    ) -> RamaTcpSessionHandle {
        let decision = engine.newTcpSession(
            meta: tcpMeta(),
            onServerBytes: { _ in .accepted },
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let session) = decision else {
            XCTFail(
                "demo handler unexpectedly returned non-intercept; tests assume tcp 443 → intercept"
            )
            preconditionFailure()
        }
        return session
    }

    // ── Box lifetime ─────────────────────────────────────────────

    /// `registerPromoteCallback` retains the closure (via the
    /// Unmanaged callback box). The session's deinit MUST release
    /// it — otherwise the closure (and anything it captures) leaks
    /// for every intercepted flow.
    func testRegisterPromoteCallbackBoxReleasedOnSessionDeinit() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var sentinel: PromoteSentinel?
        do {
            let session = newInterceptedTcpSession(on: engine)
            let s = PromoteSentinel()
            sentinel = s
            session.registerPromoteCallback { [s] in _ = s }
            XCTAssertNotNil(sentinel, "registered callback retains sentinel")
        }
        // Session out of scope → deinit released its callback box.
        XCTAssertNil(
            sentinel,
            "session deinit must release the promote callback box (sentinel still alive ⇒ leak)"
        )
    }

    /// A second `registerPromoteCallback` MUST drop the previous
    /// callback box atomically — the previous closure's captures
    /// become unreachable as soon as the new registration replaces
    /// the old. Mirrors the activate-leak regression covered for
    /// the egress callback box.
    ///
    /// The nested helpers scope the strong refs to the sentinels
    /// tightly — without that, the test's own `let s1 = …` keeps
    /// `s1` alive past the registration and the weak ref would
    /// never go nil regardless of FFI behaviour.
    func testRegisterPromoteCallbackReplacesPreviousBox() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = newInterceptedTcpSession(on: engine)

        weak var sentinel1: PromoteSentinel?
        do {
            let s1 = PromoteSentinel()
            sentinel1 = s1
            session.registerPromoteCallback { [s1] in _ = s1 }
            // Strong `s1` goes out of scope at the next brace —
            // only the closure inside the active promote box now
            // holds a reference.
        }
        XCTAssertNotNil(sentinel1, "first sentinel still held by the active box")

        weak var sentinel2: PromoteSentinel?
        do {
            let s2 = PromoteSentinel()
            sentinel2 = s2
            session.registerPromoteCallback { [s2] in _ = s2 }
        }

        // First sentinel must be released now that its box was
        // replaced by the second registration.
        XCTAssertNil(
            sentinel1,
            "second register must release the previous callback box (sentinel1 still alive ⇒ leak)"
        )
        XCTAssertNotNil(sentinel2, "second sentinel still held by the active box")

        // Hold a final strong ref so we can verify deinit-time
        // release. Drop our handle to the session by re-binding
        // the let to a new scope.
        do {
            _ = session
        }
        // Session goes out of scope at end of test → deinit will
        // run after this block; `sentinel2` becomes nil then.
        // We verify session-deinit release in
        // `testRegisterPromoteCallbackBoxReleasedOnSessionDeinit`,
        // so don't duplicate the check here.
    }

    /// `registerPromoteCallback` on a cancelled session takes the
    /// early-return path before allocating an Unmanaged box. The
    /// captured sentinel must not be retained beyond the call.
    func testRegisterAfterCancelDoesNotRetainCallback() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var sentinel: PromoteSentinel?
        do {
            let session = newInterceptedTcpSession(on: engine)
            session.cancel()
            let s = PromoteSentinel()
            sentinel = s
            session.registerPromoteCallback { [s] in _ = s }
            // No Unmanaged box should have been created — closure
            // goes out of scope at end of statement.
        }
        XCTAssertNil(
            sentinel,
            "register after cancel must not retain the callback closure"
        )
    }

    // ── No-op semantics ──────────────────────────────────────────

    /// `confirmPromoted` is documented as a no-op when no promote
    /// is in flight. From Swift's POV that means "doesn't crash, no
    /// observable side effects". We hit both the `.ok` and
    /// `.failed`-with-reason paths to verify both surface no UB.
    func testConfirmWithoutPendingIsNoOp() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = newInterceptedTcpSession(on: engine)
        // No promote ever fired — the registry's pending_ack is
        // None — but both calls must be safe.
        session.confirmPromoted(.ok)
        session.confirmPromoted(.failed, reason: "test reason — engine never fired promote")
        // Reaching here without crashing is the assertion.
    }

    /// `confirmPromoted` after cancel takes the early-return path
    /// (`cancelled` guard) and must not touch the freed Rust
    /// session pointer.
    func testConfirmAfterCancelIsNoOp() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = newInterceptedTcpSession(on: engine)
        session.cancel()
        session.confirmPromoted(.ok)
        session.confirmPromoted(.failed, reason: "after-cancel reason")
    }

    /// `registerPromoteCallback` then drop the session immediately
    /// — exercises the deinit path that releases the promote box
    /// without it ever firing.
    func testRegisterThenImmediateDeinitDoesNotLeak() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var sentinel: PromoteSentinel?
        do {
            let session = newInterceptedTcpSession(on: engine)
            let s = PromoteSentinel()
            sentinel = s
            session.registerPromoteCallback { [s] in _ = s }
            // No cancel, no activate, no bytes — just drop.
        }
        XCTAssertNil(sentinel)
    }

    // ── UTF-8 reason marshalling ─────────────────────────────────

    /// `confirmPromoted(.failed, reason:)` marshals the reason as a
    /// UTF-8 byte buffer + length (NOT NUL-terminated). Exercise a
    /// few edge cases: empty string, multi-byte unicode, embedded
    /// newline. All must reach the no-op path (no pending) without
    /// crashing.
    func testConfirmFailedReasonMarshalsUtf8Safely() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = newInterceptedTcpSession(on: engine)

        // Empty reason should take the (nil, 0) branch.
        session.confirmPromoted(.failed, reason: "")
        // ASCII.
        session.confirmPromoted(.failed, reason: "egress not ready")
        // Multi-byte UTF-8.
        session.confirmPromoted(.failed, reason: "fout — niet klaar 🚧")
        // Embedded newline + tab.
        session.confirmPromoted(.failed, reason: "line one\nline two\twith tab")
    }

    // ── Stress / churn ───────────────────────────────────────────

    /// Re-register many times on the same session; each replacement
    /// must drop the previous box. After the loop only the most
    /// recent sentinel is alive; after the session drops nothing is.
    func testManyRegisterReplacementsDoNotLeak() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var lastSentinel: PromoteSentinel?
        do {
            let session = newInterceptedTcpSession(on: engine)
            var sentinels: [PromoteSentinel] = []
            for _ in 0..<32 {
                let s = PromoteSentinel()
                sentinels.append(s)
                session.registerPromoteCallback { [s] in _ = s }
            }
            // Drop our strong refs to every sentinel except the
            // last (which the active box still owns).
            sentinels.removeAll()
            lastSentinel = nil  // never assigned strongly here

            // Now register one final callback and weak-ref its sentinel.
            let last = PromoteSentinel()
            lastSentinel = last
            session.registerPromoteCallback { [last] in _ = last }
            XCTAssertNotNil(lastSentinel, "last sentinel held by active box")
        }
        XCTAssertNil(lastSentinel, "session deinit released final promote box")
    }
}

/// Strong-ref sentinel for testing promote-callback box lifetimes.
/// Tests weak-ref it; the box (via the registered closure) is
/// expected to be the sole strong holder during the relevant
/// window.
private final class PromoteSentinel {}
