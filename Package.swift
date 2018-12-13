// swift-tools-version:4.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftJWKtoPEM",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftJWKtoPEM",
            targets: ["SwiftJWKtoPEM"]),
    ],
    dependencies: [
        .package(url: "https://github.com/IBM-Swift/OpenSSL.git", from: "2.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftJWKtoPEM",
            dependencies: ["OpenSSL"]),
        .testTarget(
            name: "SwiftJWKtoPEMTests",
            dependencies: ["SwiftJWKtoPEM"]),
    ]
)
