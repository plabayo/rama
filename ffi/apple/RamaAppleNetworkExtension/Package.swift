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
        )
    ],
    targets: [
        .target(
            name: "RamaAppleNEFFI",
            path: "Sources/RamaAppleNEFFI"
        ),
        .target(
            name: "RamaAppleNetworkExtension",
            dependencies: ["RamaAppleNEFFI"],
            path: "Sources/RamaAppleNetworkExtension"
        ),
    ]
)
