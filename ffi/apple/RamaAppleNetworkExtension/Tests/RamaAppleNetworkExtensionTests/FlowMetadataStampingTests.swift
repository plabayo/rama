import Foundation
import Network
import NetworkExtension
import ObjectiveC
import XCTest

@testable import RamaAppleNetworkExtension

/// Records stamp calls; stands in for a live `NEAppProxyFlow`.
private final class StampSpy: NSObject, EgressMetadataFlow {
    private(set) var stampCount = 0
    func stampSourceAppMetadata(onto params: NWParameters) { stampCount += 1 }
}

/// A method whose Obj-C signature matches Apple's `-[NEAppProxyFlow
/// setMetadata:]` (`nw_parameters_t`). Used to observe — safely — what
/// `perform(_:with:)` actually delivers for a Swift `NWParameters`. It only
/// reads the delivered object's class; it never treats it as an
/// `nw_parameters_t` (which is what corrupts the heap in production).
private final class SetMetadataSpy: NSObject {
    var receivedClassName: String?
    @objc(setMetadata:)
    func setMetadata(_ parameters: nw_parameters_t) {
        receivedClassName = String(cString: object_getClassName(parameters))
    }
}

/// Regression coverage for the macOS-14 new-flow crashloop. The egress
/// metadata stamp must use the typed `setMetadata(on:)` overlay on macOS 15+
/// and be omitted before macOS 15 — never forwarded to the raw
/// `-[NEAppProxyFlow setMetadata:]` selector, which takes `nw_parameters_t`
/// and, fed a Swift `NWParameters`, corrupts the heap inside
/// `nw_parameters_set_metadata`.
final class FlowMetadataStampingTests: XCTestCase {

    private func makeParams() -> NWParameters {
        NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
    }

    // MARK: - version routing (the fix)

    func testOmitsStampBeforeMacOS15() {
        // The fix: before macOS 15 the stamp is omitted entirely. Pre-fix this
        // path invoked the raw `setMetadata:` selector and corrupted the heap.
        let spy = StampSpy()
        applyFlowMetadata(spy, makeParams(), macOS15OrLater: false)
        XCTAssertEqual(
            spy.stampCount, 0,
            "metadata must NOT be stamped before macOS 15")
    }

    func testStampsViaTypedOverlayOnMacOS15Plus() {
        let spy = StampSpy()
        applyFlowMetadata(spy, makeParams(), macOS15OrLater: true)
        XCTAssertEqual(
            spy.stampCount, 1,
            "metadata must be stamped via the typed overlay on macOS 15+")
    }

    // MARK: - root cause

    /// Pins, deterministically and without a live flow, why the pre-macOS-15
    /// raw-selector path corrupted memory: a method whose Obj-C signature is
    /// Apple's `setMetadata:` (`nw_parameters_t`), invoked via
    /// `perform(_:with:)` with a Swift `NWParameters`, receives the wrapper
    /// class `Network._NWParameters` — NOT an `OS_nw_parameters`. Handing that
    /// to `nw_parameters_set_metadata` is the type confusion behind the crash,
    /// which is why `applyFlowMetadata` must never make that call.
    func testRawSetMetadataSelectorWithNWParametersIsTypeConfused() throws {
        let spy = SetMetadataSpy()
        let selector = NSSelectorFromString("setMetadata:")
        XCTAssertTrue(spy.responds(to: selector))

        spy.perform(selector, with: makeParams())

        // Coupled to Apple's private wrapper class name (`Network._NWParameters`);
        // if a future SDK renames it this characterization needs updating.
        let received = try XCTUnwrap(spy.receivedClassName)
        XCTAssertFalse(
            received.contains("OS_nw_parameters"),
            "perform(_:with:) cannot bridge; it must NOT deliver a real nw_parameters_t")
        XCTAssertTrue(
            received.contains("NWParameters"),
            "it delivers the Swift NWParameters wrapper instead (got \(received))")
    }
}
