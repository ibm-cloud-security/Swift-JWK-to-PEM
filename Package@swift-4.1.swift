// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

var dependencies: [Package.Dependency] = []
var targetDependencies: [Target.Dependency] = []

#if os(Linux)
dependencies.append(.package(url: "https://github.com/IBM-Swift/OpenSSL.git", from: "1.0.0"))
targetDependencies.append(.byName(name: "OpenSSL"))
#else
dependencies.append(.package(url: "https://github.com/IBM-Swift/OpenSSL-OSX.git", from: "0.5.0"))
#endif

let package = Package(
    name: "SwiftJWKtoPEM",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftJWKtoPEM",
            targets: ["SwiftJWKtoPEM"]),
    ],
    dependencies: dependencies,
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftJWKtoPEM",
            dependencies: targetDependencies),
        .testTarget(
            name: "SwiftJWKtoPEMTests",
            dependencies: ["SwiftJWKtoPEM"]),
    ]
)
