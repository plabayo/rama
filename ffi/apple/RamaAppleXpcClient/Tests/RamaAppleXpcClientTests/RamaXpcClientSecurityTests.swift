import XCTest
@preconcurrency import XPC

@testable import RamaAppleXpcClient

final class RamaXpcClientSecurityTests: XCTestCase {
    func testPrivilegedFlagAndPeerRequirement() throws {
        XCTAssertNotEqual(
            RamaXpcClient.machServiceFlags & UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED),
            0
        )
        XCTAssertEqual(
            try RamaXpcClient.peerCodeSigningRequirement(
                signingIdentifier: "org.example.proxy.provider",
                teamIdentifier: "A1B2C3D4E5"
            ),
            "anchor apple generic and identifier \"org.example.proxy.provider\" "
                + "and certificate leaf[subject.OU] = \"A1B2C3D4E5\""
        )
    }

    func testPeerRequirementRejectsInjectedSyntax() {
        XCTAssertThrowsError(
            try RamaXpcClient.peerCodeSigningRequirement(
                signingIdentifier: "org.example\" or true",
                teamIdentifier: "A1B2C3D4E5"
            ))
    }

    func testPeerRequirementIsAcceptedByXpc() throws {
        let requirement = try RamaXpcClient.peerCodeSigningRequirement(
            signingIdentifier: "org.example.proxy.provider",
            teamIdentifier: "A1B2C3D4E5"
        )
        let connection = xpc_connection_create_mach_service(
            "org.example.rama.unused",
            nil,
            RamaXpcClient.machServiceFlags
        )
        let status =
            requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_activate(connection)
        xpc_connection_cancel(connection)

        XCTAssertEqual(status, 0)
    }
}
