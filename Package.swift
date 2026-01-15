// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// Shared Swift settings for all targets - enables unused code warnings
let sharedSwiftSettings: [SwiftSetting] = [
    .unsafeFlags([
        "-Xfrontend", "-warn-long-function-bodies=200",
        "-Xfrontend", "-warn-long-expression-type-checking=100"
    ], .when(configuration: .debug))
]

let package = Package(
    name: "ArkavoMediaKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
        .tvOS(.v26),
    ],
    products: [
        .library(
            name: "ArkavoMediaKit",
            targets: ["ArkavoMediaKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/arkavo-org/OpenTDFKit", revision: "d8ffeff"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "ArkavoMediaKit",
            dependencies: ["OpenTDFKit"],
            swiftSettings: sharedSwiftSettings
        ),
        .executableTarget(
            name: "TestVideoGenerator",
            dependencies: [
                "ArkavoMediaKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: sharedSwiftSettings
        ),
        .testTarget(
            name: "ArkavoMediaKitTests",
            dependencies: ["ArkavoMediaKit"],
            swiftSettings: sharedSwiftSettings
        ),
    ]
)
