// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibAuk",
    platforms: [.iOS(.v15)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibAuk",
            targets: ["LibAuk"]),
    ],
    dependencies: [
        .package(url: "https://github.com/wolfmcnally/WolfBase", .exact("3.25.0")),
        .package(url: "https://github.com/bitmark-inc/Web3.swift.git", branch: "master"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", from: "2.1.0"),
        .package(url: "https://github.com/autonomy-system/kukai-core-swift.git", branch: "main"),
        .package(name: "BitmarkSDK", url: "https://github.com/bitmark-inc/bitmark-sdk-swift.git", .revision("9a602320d0908894420738f5264f60a1a089289e")),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftFoundation", from: "2.3.0")
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "LibAuk",
            dependencies: [
                .target(name: "LibWally"),
                .product(name: "Web3", package: "Web3.swift"),
                .product(name: "KukaiCoreSwift", package: "kukai-core-swift"),
                .product(name: "BitmarkSDK", package: "BitmarkSDK"),
                .product(name: "Base58Swift", package: "Base58Swift"),
                .product(name: "BCFoundation", package: "BCSwiftFoundation"),
            ]),
        .testTarget(
            name: "LibAukTests",
            dependencies: ["LibAuk"]),
        .binaryTarget(
            name: "LibWally",
            path: "Frameworks/LibWally.xcframework"),
    ],
    swiftLanguageVersions: [.v5]
)
