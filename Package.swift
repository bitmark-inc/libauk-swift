// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibAuk",
    platforms: [.iOS("16.0")],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibAuk",
            targets: ["LibAuk"]),
    ],
    dependencies: [
        .package(name: "Web3.swift", url: "https://github.com/bitmark-inc/Web3.swift.git", branch: "migrate_secp256"),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "14.0.2"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", from: "2.1.0"),
        .package(name: "KukaiCoreSwift", url: "https://github.com/autonomy-system/kukai-core-swift.git", branch: "migrate_secp256"),
        .package(name: "TweetNacl", url: "https://github.com/bitmark-inc/tweetnacl-swiftwrap", branch: "master"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftFoundation.git", branch: "master")
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "LibAuk",
            dependencies: [
                .product(name: "Web3", package: "Web3.swift"),
                .product(name: "URKit", package: "URKit"),
                .product(name: "Base58Swift", package: "Base58Swift"),
                .product(name: "KukaiCoreSwift", package: "KukaiCoreSwift"),
                .product(name: "TweetNacl", package: "TweetNacl"),
                .product(name: "BCFoundation", package: "BCSwiftFoundation")
            ]),
        .testTarget(
            name: "LibAukTests",
            dependencies: ["LibAuk"])
    ],
    swiftLanguageVersions: [.v5]
)
