// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

final class CaptivePortalDirectDoHWiringTests: XCTestCase {
    func testDetectorUsesDirectProviderProbeWithoutLoopbackOrDig() throws {
        let detector = try source(
            "Sources/MacDNSAgent/Services/CaptivePortalDetector.swift"
        )

        XCTAssertTrue(detector.contains("probeRecursiveResolution()"))
        for forbidden in ["Process()", "/usr/bin/dig", "@127.0.0.1", "stale from"] {
            XCTAssertFalse(
                detector.localizedCaseInsensitiveContains(forbidden),
                "detector must not derive health from \(forbidden)"
            )
        }
    }

    func testDetectorIsTheOnlyDirectProbeCaller() throws {
        let directory = repositoryRoot.appendingPathComponent(
            "Sources/MacDNSAgent"
        )
        let enumerator = try XCTUnwrap(
            FileManager.default.enumerator(
                at: directory,
                includingPropertiesForKeys: nil
            )
        )
        var callers: [String] = []
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            let contents = try String(contentsOf: file, encoding: .utf8)
            if contents.contains("probeRecursiveResolution()") {
                callers.append(file.lastPathComponent)
            }
        }

        XCTAssertEqual(
            callers.sorted(),
            ["CaptivePortalDetector.swift", "ResolverModule.swift"]
        )
    }

    func testRustProbeBypassesLocalCacheForwardingAndListeners() throws {
        let query = try source(
            "rust-resolver/crates/macdns-resolver/src/query.rs"
        )
        let start = try XCTUnwrap(
            query.range(of: "pub(crate) async fn probe_recursive_resolution")
        )
        let remainder = query[start.lowerBound...]
        let end = try XCTUnwrap(
            remainder.range(of: "\nfn direct_doh_probe_failure_class")
        )
        let body = String(remainder[..<end.lowerBound])

        XCTAssertTrue(body.contains("dispatch("))
        XCTAssertTrue(body.contains("&state.pool"))
        for forbidden in ["handle_wire", "state.cache", "state.forward", "listener"] {
            XCTAssertFalse(body.contains(forbidden))
        }

        let providers = try source(
            "rust-resolver/crates/macdns-resolver/src/providers.rs"
        )
        XCTAssertTrue(providers.contains("o.cache_size = 0;"))
        XCTAssertTrue(
            providers.contains("fn provider_budget_is_single_shot_and_bounded()")
        )
    }

    func testDirectProbeLogsFailuresWithoutLoggingRoutineSuccess() throws {
        let query = try source(
            "rust-resolver/crates/macdns-resolver/src/query.rs"
        )
        let start = try XCTUnwrap(
            query.range(of: "pub(crate) async fn probe_recursive_resolution")
        )
        let remainder = query[start.lowerBound...]
        let end = try XCTUnwrap(
            remainder.range(of: "\nfn direct_doh_probe_failure_class")
        )
        let body = String(remainder[..<end.lowerBound])

        XCTAssertFalse(body.contains("log::info!"))
        XCTAssertFalse(body.contains("winner="))
        XCTAssertTrue(body.contains("log::warn!"))
        XCTAssertTrue(body.contains("failure={}"))
        XCTAssertTrue(body.contains("duration_ms={}"))
    }

    func testCompatibilityProbesTheResolversForwardingWouldUse() throws {
        let probe = try methodBody(
            declaration: "private func probeNetworkDNSIfNeeded",
            in: "Sources/MacDNSAgent/Services/CaptivePortalDetector.swift"
        )
        XCTAssertTrue(probe.contains("CaptiveConnectivityPolicy.needsNetworkDNSProbe("))
        XCTAssertTrue(probe.contains("NetworkMonitor.getDHCPDNSServers()"))
        XCTAssertTrue(probe.contains("probeNetworkDNS(servers: servers)"))

        let handler = try methodBody(
            declaration: "private func handleNetworkCompatibilityRequired",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        XCTAssertTrue(handler.contains("NetworkMonitor.getDHCPDNSServers()"))

        let forward = try source(
            "rust-resolver/crates/macdns-resolver/src/forward.rs"
        )
        XCTAssertTrue(forward.contains("ForwardResolver::build(servers, port)"))
        XCTAssertTrue(forward.contains("opts.cache_size = 0;"))
    }

    func testWakePathOnlyRequestsARecheck() throws {
        let body = try methodBody(
            declaration: "func systemDidWake",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(body.contains("trigger: .wake"))
        XCTAssertFalse(body.contains("notifyNetworkChange"))
        XCTAssertFalse(body.contains("flushCache"))
    }

    func testDirectDoHRecoveryKeepsTheProvenProviderPath() throws {
        let body = try methodBody(
            declaration: "private func completeVerifiedDirectDoHRecovery",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(body.contains("completeDirectDoHRecovery"))
        XCTAssertFalse(body.contains("notifyNetworkChange"))
    }

    func testServiceStartRecheckFollowsSessionInstallation() throws {
        let agent = try source("Sources/MacDNSAgent/MacDNSAgent.swift")
        let session = try XCTUnwrap(
            agent.range(of: "ProxyControlClient.shared.ensureSessionInstalled()")
        )
        let recheck = try XCTUnwrap(
            agent.range(
                of: "enqueueCaptivePortalRecheck(\n                trigger: .serviceStart",
                range: session.upperBound..<agent.endIndex
            )
        )

        XCTAssertLessThan(session.lowerBound, recheck.lowerBound)
    }

    func testResolverPreparationStaysBehindTheApprovedBypass() throws {
        let body = try methodBody(
            declaration: "private func prepareResolverForCaptiveProbe",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(body.contains("guard captiveFullBypassIsAuthorized()"))
        XCTAssertTrue(body.contains("keepProxyBypass: true"))
        XCTAssertTrue(body.contains("defer"))
        XCTAssertTrue(body.contains("isPreparingCaptiveResolver = false"))
    }

    func testResolverPreparationFailureUsesABoundedDelayedRetry() throws {
        let detector = try source(
            "Sources/MacDNSAgent/Services/CaptivePortalDetector.swift"
        )
        let body = try methodBody(
            declaration: "func scheduleRetryAfterResolverPreparationFailure",
            in: "Sources/MacDNSAgent/Services/CaptivePortalDetector.swift"
        )

        XCTAssertTrue(body.contains("failureCount < maxFailures"))
        XCTAssertTrue(body.contains("config.errorRetryInterval"))
        XCTAssertTrue(detector.contains("preserving approved captive bypass"))
    }

    private var repositoryRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 {
            url.deleteLastPathComponent()
        }
        return url
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func methodBody(
        declaration: String,
        in relativePath: String
    ) throws -> String {
        let contents = try source(relativePath)
        let start = try XCTUnwrap(contents.range(of: declaration))
        let remainder = contents[start.upperBound...]
        let end = try XCTUnwrap(remainder.range(of: "\n    }"))
        return String(remainder[..<end.lowerBound])
    }
}
