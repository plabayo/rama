// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "RamaAppleNetworkExtension",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "RamaAppleNetworkExtension",
            targets: ["RamaAppleNetworkExtension"]
        ),
        .library(
            name: "RamaAppleSecureEnclave",
            targets: ["RamaAppleSecureEnclave"]
        ),
        .library(
            name: "RamaAppleXpcClient",
            targets: ["RamaAppleXpcClient"]
        ),
    ],
    targets: [
        .target(
            name: "RamaAppleNEFFI",
            path: "ffi/apple/RamaAppleNetworkExtension/Sources/RamaAppleNEFFI",
            linkerSettings: [
                .linkedLibrary("bsm"),
                .linkedLibrary("proc"),
            ]
        ),
        .target(
            name: "RamaAppleNetworkExtension",
            dependencies: ["RamaAppleNEFFI"],
            path: "ffi/apple/RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension"
        ),
        .target(
            name: "RamaAppleSEFFI",
            path: "ffi/apple/RamaAppleSecureEnclave/Sources/RamaAppleSEFFI"
        ),
        .target(
            name: "RamaAppleSecureEnclave",
            dependencies: ["RamaAppleSEFFI"],
            path: "ffi/apple/RamaAppleSecureEnclave/Sources/RamaAppleSecureEnclave"
        ),
        .target(
            name: "RamaAppleXpcClient",
            path: "ffi/apple/RamaAppleXpcClient/Sources/RamaAppleXpcClient"
        ),
        // Swift FFI integration tests. Drive them via `just test-swift-ffi`
        // (or `test-swift-ffi-asan` for sanitizer builds) so the rama
        // staticlib path stays in one place. CI uses the same recipes.
        .testTarget(
            name: "RamaAppleNetworkExtensionTests",
            dependencies: ["RamaAppleNetworkExtension", "RamaAppleSecureEnclave"],
            path: "ffi/apple/RamaAppleNetworkExtension/Tests/RamaAppleNetworkExtensionTests"
        ),
    ]
)
