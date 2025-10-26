// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

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
        .package(url: "https://github.com/arkavo-org/OpenTDFKit", branch: "main"),
    ],
    targets: [
        .target(
            name: "ArkavoMediaKit",
            dependencies: ["OpenTDFKit"]
        ),
        .testTarget(
            name: "ArkavoMediaKitTests",
            dependencies: ["ArkavoMediaKit"]
        ),
    ]
)
