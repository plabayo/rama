import Foundation
import OSLog

extension ContainerController {
    func log(_ message: String) {
        containerLogger.info("\(message, privacy: .public)")
        appendLogLine("INFO", message)
    }

    func appendLogLine(_ level: String, _ message: String) {
        let formatter = ISO8601DateFormatter()
        let line = "[\(formatter.string(from: Date()))] \(level): \(message)\n"
        let data = Data(line.utf8)

        do {
            let dir = logFileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: logFileURL.path) {
                FileManager.default.createFile(atPath: logFileURL.path, contents: nil)
            }
            let handle = try FileHandle(forWritingTo: logFileURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            containerLogger.error(
                "failed to append container log file: \(String(describing: error), privacy: .public)")
        }
    }

    func logDisconnectReason(_ error: Error) {
        let ns = error as NSError
        let classification = classifyDisconnectReason(ns)
        let message =
            "status=disconnected reason: classification=\(classification) domain=\(ns.domain) code=\(ns.code) description=\(ns.localizedDescription) userInfo=\(String(describing: ns.userInfo))"
        containerLogger.error("\(message, privacy: .public)")
        appendLogLine("ERROR", message)
    }

    func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        let message =
            "\(prefix): domain=\(ns.domain) code=\(ns.code) description=\(ns.localizedDescription) userInfo=\(String(describing: ns.userInfo))"
        containerLogger.error("\(message, privacy: .public)")
        appendLogLine("ERROR", message)
    }

    func logErrorText(_ message: String) {
        containerLogger.error("\(message, privacy: .public)")
        appendLogLine("ERROR", message)
    }

    func classifyDisconnectReason(_ error: NSError) -> String {
        switch error.domain {
        case "NEVPNConnectionErrorDomainPlugin":
            return
                "extension/plugin startup failure; provider likely failed before it could report its own NSError"
        case "NEVPNConnectionErrorDomain":
            return classifySystemDisconnectReason(code: error.code)
        default:
            return
                "provider-reported disconnect or nonstandard NetworkExtension error; inspect domain/code directly"
        }
    }

    func classifySystemDisconnectReason(code: Int) -> String {
        switch code {
        case 1: return "system sleep interrupted the VPN session"
        case 2: return "no network was available to establish the VPN session"
        case 3: return "network conditions changed and the VPN session could not be maintained"
        case 4: return "VPN configuration was invalid"
        case 5: return "VPN server address resolution failed"
        case 6: return "VPN server did not respond"
        case 7: return "VPN server is no longer functioning"
        case 8: return "VPN authentication failed"
        case 9: return "client certificate is invalid"
        case 10: return "client certificate is not yet valid"
        case 11: return "client certificate expired"
        case 12: return "VPN plugin died unexpectedly"
        case 13: return "VPN configuration could not be found"
        case 14: return "VPN plugin is disabled or unavailable"
        case 15: return "VPN protocol negotiation failed"
        case 16: return "VPN server disconnected the session"
        case 17: return "VPN server certificate is invalid"
        case 18: return "VPN server certificate is not yet valid"
        case 19: return "VPN server certificate expired"
        default: return "unknown system VPN disconnect reason"
        }
    }
}
