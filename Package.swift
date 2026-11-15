// swift-tools-version: 5.9
// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import PackageDescription

let package = Package(
    name: "MacDNS",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "MacDNS", targets: ["MacDNS"]),
        .executable(name: "MacDNSAgent", targets: ["MacDNSAgent"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-format", from: "604.0.0"),
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.10.1")
    ],
    targets: [
        .target(
            name: "Shared",
            dependencies: []
        ),

        // Assets.xcassets lives in Icons/ and is compiled by the Makefile, not by SPM.
        .executableTarget(
            name: "MacDNS",
            dependencies: [
                "Shared",
                .product(name: "Sparkle", package: "Sparkle")
            ],
            exclude: ["Makefile"]
        ),

        .executableTarget(
            name: "MacDNSAgent",
            dependencies: [
                "Shared"
            ]
        ),

        // Process-identity primitives both NetworkExtension providers need.
        //
        // The shipped providers are built by a bare `swiftc Sources/<Ext>/*.swift`
        // (see Sources/MacDNS/Makefile) with no module to import, so that build
        // compiles these files straight into each provider. The sources wrap the
        // import in `#if canImport` so one copy serves both builds. SPM does not
        // allow one directory in two targets, which forces this separate target.
        .target(
            name: "SharedExtensionKit",
            dependencies: [],
            path: "Sources/SharedExtensionKit"
        ),

        // The shipped .systemextension bundles for both providers are built by the
        // Makefile. These SPM targets exist so tests can import the provider code.
        .target(
            name: "DNSProxyExtension",
            dependencies: ["SharedExtensionKit"],
            path: "Sources/DNSProxyExtension",
            exclude: ["Info.plist", "main.swift"],
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .target(
            name: "ContentFilterExtension",
            dependencies: ["SharedExtensionKit"],
            path: "Sources/ContentFilterExtension",
            exclude: ["Info.plist", "main.swift"],
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "MacDNSTests",
            dependencies: [
                "Shared",
                "SharedExtensionKit",
                "MacDNS",
                "MacDNSAgent",
                "DNSProxyExtension",
                "ContentFilterExtension",
            ]
        ),
    ]
)
