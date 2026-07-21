// swift-tools-version:6.0
import PackageDescription

// SynoKit is the transport/security core shared between SynologyMonitor and
// SynologyPhotosManager: DSM authentication (incl. 2FA), runtime API discovery,
// per-host TLS trust (TOFU pinning), and the AES-GCM local credential store.
// App-specific APIs (SYNO.Foto.*, SYNO.DownloadStation.*, …) and their error
// mappers live in the host apps, not here.
//
// Tests run through the `SynoKitChecks` executable (a dependency-free harness)
// so they work under a bare Command Line Tools toolchain, where SwiftPM's
// `swift test` can't load XCTest / discover swift-testing tests. Run with:
//   swift run SynoKitChecks
//
// NOTE: language mode is v5 for now; migrating to Swift 6 strict concurrency is
// a tracked follow-up (runtime types are already @unchecked Sendable / actors).
let package = Package(
    name: "SynoKit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SynoKit", targets: ["SynoKit"]),
    ],
    targets: [
        .target(
            name: "SynoKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "SynoKitChecks",
            dependencies: ["SynoKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
