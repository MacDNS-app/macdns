// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class DNSProxyProviderProcessInspectorTests: XCTestCase {
    func testProviderExecutablePathMatchesInstalledSysextBinary() {
        XCTAssertTrue(
            DNSProxyProviderProcessInspector.isProviderExecutablePath(
                "/Library/SystemExtensions/0A1B2C3D-0000-0000-0000-000000000000/"
                    + "app.macdns.dnsproxy.systemextension/Contents/MacOS/app.macdns.dnsproxy"
            )
        )
    }

    func testProviderExecutablePathRejectsOtherBinaries() {
        XCTAssertFalse(
            DNSProxyProviderProcessInspector.isProviderExecutablePath(
                "/Library/SystemExtensions/0A1B2C3D-0000-0000-0000-000000000000/"
                    + "app.macdns.contentfilter.systemextension/Contents/MacOS/app.macdns.contentfilter"
            )
        )
        XCTAssertFalse(
            DNSProxyProviderProcessInspector.isProviderExecutablePath(
                "/Applications/MacDNS.app/Contents/MacOS/app.macdns.dnsproxy"
            )
        )
        XCTAssertFalse(DNSProxyProviderProcessInspector.isProviderExecutablePath(""))
    }

    func testWaitForProviderExitReturnsTrueOnceProbeReportsExit() async {
        let calls = ProbeCounter()
        let exited = await DNSProxyProviderProcessInspector.waitForProviderExit(
            timeout: 5,
            pollInterval: 0.01,
            isRunning: { calls.next() < 3 }
        )
        XCTAssertTrue(exited)
    }

    func testCanceledWaitDoesNotProbeOrSpin() async {
        let calls = ProbeCounter()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await DNSProxyProviderProcessInspector.waitForProviderExit(
                timeout: 0.01, pollInterval: 0.001,
                isRunning: {
                    _ = calls.next()
                    return true
                })
        }
        let exited = await task.value
        XCTAssertFalse(exited)
        XCTAssertEqual(calls.next(), 1)
    }

    func testWaitForProviderExitReturnsFalseOnTimeout() async {
        let exited = await DNSProxyProviderProcessInspector.waitForProviderExit(
            timeout: 0.05,
            pollInterval: 0.01,
            isRunning: { true }
        )
        XCTAssertFalse(exited)
    }
}

private final class ProbeCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func next() -> Int {
        lock.withLock {
            count += 1
            return count
        }
    }
}
