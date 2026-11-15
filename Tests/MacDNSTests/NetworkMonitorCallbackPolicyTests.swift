// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

/// Records every configuration read so the test can prove none of them happen
/// while the SCDynamicStore callback is still on the stack.
private final class RecordingConfigurationReader: NetworkConfigurationReading {
    private let lock = NSLock()
    private var reads: [String] = []
    private let onRead: (String) -> Void
    private let values: [String: [String: Any]]

    init(
        values: [String: [String: Any]] = [:],
        onRead: @escaping (String) -> Void
    ) {
        self.values = values
        self.onRead = onRead
    }

    var readCount: Int {
        lock.withLock { reads.count }
    }

    var readKeys: [String] {
        lock.withLock { reads }
    }

    func copyValue(forKey key: String) -> [String: Any]? {
        lock.withLock { reads.append(key) }
        onRead(key)
        return values[key]
    }
}

private final class RecordingNetworkMonitorDelegate: NetworkMonitorDelegate {
    private let lock = NSLock()
    private(set) var configurations: [(Bool, UInt64)] = []
    var onConfiguration: (() -> Void)?

    func networkStatusChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {}

    func networkConfigurationChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {
        lock.withLock {
            configurations.append((isConnected, callbackLifecycleGeneration))
        }
        onConfiguration?()
    }

    var recordedConfigurations: [(Bool, UInt64)] {
        lock.withLock { configurations }
    }
}

final class NetworkMonitorCallbackPolicyTests: XCTestCase {
    func testConfigurationCallbackDoesNotReadOnItsSynchronousCallStack() {
        let deferredReads = expectation(description: "configuration read on a later queue turn")
        deferredReads.expectedFulfillmentCount = 2
        let callbackMarker = "NetworkMonitorCallbackPolicyTests.\(UUID().uuidString)"
        let reader = RecordingConfigurationReader { _ in
            XCTAssertNil(
                Thread.current.threadDictionary[callbackMarker],
                "SCDynamicStore must not be read on the callback's synchronous call stack"
            )
            deferredReads.fulfill()
        }
        let monitor = NetworkMonitor(reader: reader, callbackLifecycleGeneration: 7)
        defer { monitor.stop() }

        do {
            Thread.current.threadDictionary[callbackMarker] = true
            defer { Thread.current.threadDictionary.removeObject(forKey: callbackMarker) }
            monitor.enqueueConfigurationChange(
                changedKeys: [NetworkReachabilitySnapshot.ipv4GlobalKey]
            )
        }

        wait(for: [deferredReads], timeout: 2.0)

        XCTAssertEqual(
            reader.readKeys,
            [
                NetworkReachabilitySnapshot.ipv4GlobalKey,
                NetworkReachabilitySnapshot.ipv6GlobalKey,
            ]
        )
    }

    func testIrrelevantConfigurationKeysAreIgnoredInTheDeferredTurn() {
        let reader = RecordingConfigurationReader { _ in
            XCTFail("Unrelated configuration keys must not trigger a read")
        }
        let monitor = NetworkMonitor(reader: reader, callbackLifecycleGeneration: 7)
        defer { monitor.stop() }

        monitor.enqueueConfigurationChange(changedKeys: ["State:/Network/Interface"])

        let drained = expectation(description: "queued work finished")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { drained.fulfill() }
        wait(for: [drained], timeout: 2.0)

        XCTAssertEqual(reader.readCount, 0)
    }

    func testRebindCancelsConfigurationCallbackFromPreviousLifecycle() {
        let reader = RecordingConfigurationReader(
            values: [
                NetworkReachabilitySnapshot.ipv4GlobalKey: [
                    "PrimaryInterface": "en0",
                    "PrimaryService": "wifi",
                ]
            ]
        ) { _ in }
        let monitor = NetworkMonitor(
            reader: reader,
            callbackLifecycleGeneration: 7,
            debounceDelay: 0.05
        )
        let delegate = RecordingNetworkMonitorDelegate()
        monitor.delegate = delegate
        defer { monitor.stop() }

        monitor.enqueueConfigurationChange(
            changedKeys: [NetworkReachabilitySnapshot.ipv4GlobalKey]
        )
        XCTAssertTrue(monitor.start(callbackLifecycleGeneration: 8))

        let staleWindow = expectation(description: "stale callback window elapsed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            staleWindow.fulfill()
        }
        wait(for: [staleWindow], timeout: 1.0)
        XCTAssertTrue(delegate.recordedConfigurations.isEmpty)
    }

    func testConfigurationCallbackCarriesStoredReachability() {
        let reader = RecordingConfigurationReader(
            values: [
                NetworkReachabilitySnapshot.ipv4GlobalKey: [
                    "PrimaryInterface": "en0",
                    "PrimaryService": "wifi",
                ]
            ]
        ) { _ in }
        let monitor = NetworkMonitor(
            reader: reader,
            callbackLifecycleGeneration: 9
        )
        let delegate = RecordingNetworkMonitorDelegate()
        let delivered = expectation(description: "configuration delivered")
        delegate.onConfiguration = { delivered.fulfill() }
        monitor.delegate = delegate
        defer { monitor.stop() }

        monitor.enqueueConfigurationChange(
            changedKeys: [NetworkReachabilitySnapshot.ipv4GlobalKey]
        )

        wait(for: [delivered], timeout: 1.0)
        XCTAssertEqual(delegate.recordedConfigurations.count, 1)
        XCTAssertEqual(delegate.recordedConfigurations.first?.0, true)
        XCTAssertEqual(delegate.recordedConfigurations.first?.1, 9)
        XCTAssertTrue(monitor.isConnected)
    }
}
