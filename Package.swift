// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibAuk",
    platforms: [.iOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibAuk",
            targets: ["LibAuk"]),
    ],
    dependencies: [
        .package(name: "Web3", url: "https://github.com/bitmark-inc/Web3.swift.git", .branch("master")),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", .exact("2.4.0")),
        .package(name: "KukaiCoreSwift", url: "https://github.com/hvthhien/kukai-core-swift.git", .revision("549a9b9faee0c292c94b65db08e0cb464e18cbf6"))
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
                .product(name: "Web3", package: "Web3"),
                .product(name: "URKit", package: "URKit"),
                .product(name: "KukaiCoreSwift", package: "KukaiCoreSwift"),
            ]),
        .testTarget(
            name: "LibAukTests",
            dependencies: ["LibAuk"]),
        .binaryTarget(
            name: "LibWally",
            path: "Frameworks/LibWally.xcframework")
    ],
    swiftLanguageVersions: [.v5]
)
