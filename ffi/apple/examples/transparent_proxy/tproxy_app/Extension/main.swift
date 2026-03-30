import Foundation
import NetworkExtension
import OSLog

private let bootstrapLogger = Logger(
    subsystem: "org.ramaproxy.example.tproxy",
    category: "extension-swift"
)

private func main() -> Never {
    bootstrapLogger.info("will start system extension mode")
    autoreleasepool {
        NEProvider.startSystemExtensionMode()
    }
    bootstrapLogger.info("will start dispatch main")
    dispatchMain()
}

main()
