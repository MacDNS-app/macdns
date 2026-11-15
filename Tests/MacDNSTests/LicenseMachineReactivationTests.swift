// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class LicenseURLProtocolStub: URLProtocol {
    private static let handlerLock = NSLock()
    private nonisolated(unsafe) static var _handler:
        (
            (URLRequest) throws -> (HTTPURLResponse, Data)
        )?

    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))? {
        get {
            handlerLock.lock()
            defer { handlerLock.unlock() }
            return _handler
        }
        set {
            handlerLock.lock()
            _handler = newValue
            handlerLock.unlock()
        }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        do {
            guard let handler = Self.handler else {
                throw URLError(.badServerResponse)
            }
            let (response, data) = try handler(request)
            client?.urlProtocol(
                self,
                didReceive: response,
                cacheStoragePolicy: .notAllowed
            )
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }

    func currentValue() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class LockedValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    func set(_ newValue: Value) {
        lock.withLock { value = newValue }
    }

    func get() -> Value {
        lock.withLock { value }
    }
}

private final class LockedFingerprints: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    func append(_ value: String) {
        lock.lock()
        storage.append(value)
        lock.unlock()
    }

    func values() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

final class LicenseMachineReactivationTests: XCTestCase {
    private static let testSemaphore = DispatchSemaphore(value: 1)
    private static let signer = LicenseTestResponseSigner()
    /// Most tests assert the immediate outcome of one validation, so the
    /// license-owned retry loop is kept out of the way.
    private static let disabledRetryPolicy = LicenseRetryPolicy(maxAttempts: 0)
    /// Retries immediately, for the tests that assert recovery itself.
    private static let immediateRetryPolicy = LicenseRetryPolicy(
        baseDelay: 0,
        maxAttempts: 3,
        sleep: { _ in }
    )

    private struct TestContext {
        let directory: URL
        let licensePath: URL
        let manager: LicenseManager
    }

    override func setUp() {
        super.setUp()
        Self.testSemaphore.wait()
    }

    override func tearDown() {
        LicenseURLProtocolStub.handler = nil
        Self.testSemaphore.signal()
        super.tearDown()
    }

    func testManagerCanUseInjectedLicensePathAndSession() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }

        await context.manager.initialize()

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: context.licensePath.path)
        )
    }

    func testPublicReadImplicitlyWaitsForInitialization() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }

        let info = await context.manager.getLicenseInfo()

        XCTAssertEqual(info.status, .valid)
        XCTAssertEqual(info.licenseKey, "paid-key")
        XCTAssertTrue(info.isServiceAllowed)
    }

    func testRecurringValidationReactivatesMissingMachine() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.machineId, "machine-new")
        XCTAssertEqual(saved.machineReactivationPending, false)
        XCTAssertEqual(saved.status, .valid)
    }

    func testMachineLimitBlocksServiceWithoutReplacingMachine() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 422,
                    body: Self.machineLimitBody
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.machineId)
        XCTAssertEqual(saved.machineReactivationPending, true)
        XCTAssertEqual(saved.status, .invalid)
    }

    /// The server reported that this machine has no seat. Grace must not cover
    /// it until reactivation succeeds, or a revoked seat keeps running for the
    /// whole 72h window by staying offline.
    func testMachineActivationTransportFailureIsNotCoveredByGracePeriod() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            }
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()
        let serviceAllowed = await context.manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.machineId)
        XCTAssertEqual(saved.machineReactivationPending, true)
        XCTAssertEqual(saved.status, .valid)
    }

    func testAlreadyActivatedMachineIDIsPersisted() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 422,
                    body: Self.fingerprintTakenBody
                )
            case ("GET", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: #"{"data":[{"id":"machine-existing"}]}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.machineId, "machine-existing")
        XCTAssertEqual(saved.machineReactivationPending, false)
        XCTAssertEqual(saved.status, .valid)
    }

    func testPerpetualValidationClearsOldExpiry() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.expiresAt)
    }

    func testReactivationCallbackObservesPersistedMachine() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let validationCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                if validationCount.increment() == 1 {
                    return Self.response(
                        for: request,
                        statusCode: 200,
                        body:
                            #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                    )
                }
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let initiallyAllowed = await context.manager.ensureValidLicense()
        XCTAssertTrue(initiallyAllowed)

        let callback = expectation(description: "reactivation callback")
        context.manager.onStatusChange = { _, _ in
            do {
                let saved = try self.savedState(at: context.licensePath)
                XCTAssertEqual(saved.machineId, "machine-new")
            } catch {
                XCTFail("Failed to load persisted license state: \(error)")
            }
            callback.fulfill()
        }

        let recoveredAllowed = await context.manager.ensureValidLicense()
        XCTAssertTrue(recoveredAllowed)
        await fulfillment(of: [callback], timeout: 1)
    }

    func testExistingMachineLookupTransportFailureIsNotCoveredByGracePeriod() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 422,
                    body: Self.fingerprintTakenBody
                )
            case ("GET", let path?) where path.hasSuffix("/machines"):
                throw URLError(.notConnectedToInternet)
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.machineId)
        XCTAssertEqual(saved.machineReactivationPending, true)
        XCTAssertEqual(saved.status, .valid)
    }

    func testExistingMachineLookupTransientResponsesAreNotCoveredByGracePeriod()
        async throws
    {
        for statusCode in [408, 429, 500, 503, 599] {
            let lastValidatedAt = Date(
                timeIntervalSince1970: floor(Date().timeIntervalSince1970) - 60
            )
            let initialState = paidState(lastValidatedAt: lastValidatedAt)
            let context = try makeContext(initialState: initialState)
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { request in
                switch (request.httpMethod, request.url?.path) {
                case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                    return Self.response(
                        for: request,
                        statusCode: 200,
                        body:
                            #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                    )
                case ("POST", let path?) where path.hasSuffix("/machines"):
                    return Self.response(
                        for: request,
                        statusCode: 409,
                        body: #"{"errors":[{"detail":"Machine already exists"}]}"#
                    )
                case ("GET", let path?) where path.hasSuffix("/machines"):
                    return Self.response(
                        for: request,
                        statusCode: statusCode,
                        body: ""
                    )
                default:
                    throw URLError(.badURL)
                }
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertFalse(
                allowed,
                "HTTP \(statusCode) must not admit a machine without a seat"
            )
            let saved = try savedState(at: context.licensePath)
            XCTAssertNil(saved.machineId)
            XCTAssertEqual(saved.machineReactivationPending, true)
            XCTAssertEqual(saved.status, .valid)
            XCTAssertEqual(saved.lastValidatedAt, lastValidatedAt)
        }
    }

    func testExistingMachineLookupTransientResponseOutsideGraceDoesNotPersistInvalidState()
        async throws
    {
        let lastValidatedAt = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970) - (73 * 60 * 60)
        )
        let initialState = paidState(lastValidatedAt: lastValidatedAt)
        let context = try makeContext(initialState: initialState)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 409,
                    body: #"{"errors":[{"detail":"Machine already exists"}]}"#
                )
            case ("GET", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 503,
                    body: ""
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()
        let info = await context.manager.getLicenseInfo()

        XCTAssertFalse(allowed)
        XCTAssertFalse(info.isServiceAllowed)
        XCTAssertEqual(info.status, .valid)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.machineId)
        XCTAssertEqual(saved.machineReactivationPending, true)
        XCTAssertEqual(saved.status, .valid)
        XCTAssertEqual(saved.lastValidatedAt, lastValidatedAt)
    }

    func testConflictPointerIsNotPersistedAsMachineID() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 409,
                    body:
                        #"{"errors":[{"source":{"pointer":"/data/attributes/fingerprint"}}]}"#
                )
            case ("GET", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: #"{"data":[{"id":"machine-existing"}]}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.machineId, "machine-existing")
    }

    func testExpiredNetworkGraceBlocksScheduledValidation() async throws {
        let expiredGrace = Date().addingTimeInterval(-(73 * 60 * 60))
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: expiredGrace)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        await context.manager.initialize()
        let callback = expectation(description: "expired grace callback")
        context.manager.onStatusChange = { _, allowed in
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let info = await context.manager.validateLicense()

        XCTAssertFalse(info.isServiceAllowed)
        await fulfillment(of: [callback], timeout: 1)
    }

    func testSuccessfulValidationRestoresServiceAfterExpiredGrace() async throws {
        let expiredGrace = Date().addingTimeInterval(-(73 * 60 * 60))
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: expiredGrace)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if requestCount.increment() == 1 {
                throw URLError(.notConnectedToInternet)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }
        await context.manager.initialize()
        let blockedCallback = expectation(description: "service blocked")
        let restoredCallback = expectation(description: "service restored")
        let callbackCount = LockedCounter()
        context.manager.onStatusChange = { _, allowed in
            if callbackCount.increment() == 1 {
                XCTAssertFalse(allowed)
                blockedCallback.fulfill()
            } else {
                XCTAssertTrue(allowed)
                restoredCallback.fulfill()
            }
        }

        let blockedInfo = await context.manager.validateLicense()
        XCTAssertFalse(blockedInfo.isServiceAllowed)
        await fulfillment(of: [blockedCallback], timeout: 1)

        let restoredInfo = await context.manager.validateLicense()
        XCTAssertTrue(restoredInfo.isServiceAllowed)
        await fulfillment(of: [restoredCallback], timeout: 1)
    }

    func testConcurrentValidationReusesExpiredGraceDecision() async throws {
        let expiredGrace = Date().addingTimeInterval(-(73 * 60 * 60))
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: expiredGrace)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestStarted = DispatchSemaphore(value: 0)
        let releaseRequest = DispatchSemaphore(value: 0)
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            if requestCount.increment() == 1 {
                requestStarted.signal()
                _ = releaseRequest.wait(timeout: .now() + 2)
            }
            throw URLError(.notConnectedToInternet)
        }

        let firstValidation = Task {
            await context.manager.ensureValidLicense()
        }
        XCTAssertEqual(requestStarted.wait(timeout: .now() + 1), .success)
        let secondValidation = Task {
            await context.manager.ensureValidLicense()
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        releaseRequest.signal()

        let firstAllowed = await firstValidation.value
        let secondAllowed = await secondValidation.value

        XCTAssertFalse(firstAllowed)
        XCTAssertFalse(secondAllowed)
        XCTAssertEqual(requestCount.currentValue(), 1)
    }

    func testManualAndEnsureValidationShareTheSameGate() async throws {
        let expiredGrace = Date().addingTimeInterval(-(73 * 60 * 60))
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: expiredGrace)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        let requestStarted = DispatchSemaphore(value: 0)
        let releaseRequest = DispatchSemaphore(value: 0)
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if requestCount.increment() == 1 {
                requestStarted.signal()
                _ = releaseRequest.wait(timeout: .now() + 2)
                throw URLError(.notConnectedToInternet)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let manualValidation = Task {
            await context.manager.validateLicense()
        }
        XCTAssertEqual(requestStarted.wait(timeout: .now() + 1), .success)
        let ensureValidation = Task {
            await context.manager.ensureValidLicense()
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        releaseRequest.signal()

        let manualInfo = await manualValidation.value
        let ensureAllowed = await ensureValidation.value

        XCTAssertFalse(manualInfo.isServiceAllowed)
        XCTAssertFalse(ensureAllowed)
        XCTAssertEqual(requestCount.currentValue(), 1)
    }

    func testActivationDoesNotRaceAnExistingValidation() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        let requestStarted = DispatchSemaphore(value: 0)
        let releaseRequest = DispatchSemaphore(value: 0)
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if requestCount.increment() == 1 {
                requestStarted.signal()
                _ = releaseRequest.wait(timeout: .now() + 2)
                throw URLError(.notConnectedToInternet)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-new","attributes":{}}}"#
            )
        }

        let validation = Task {
            await context.manager.validateLicense()
        }
        XCTAssertEqual(requestStarted.wait(timeout: .now() + 1), .success)

        let activation = await context.manager.activateLicense(key: "new-key")
        releaseRequest.signal()
        _ = await validation.value

        guard case .error = activation else {
            return XCTFail("Activation must not bypass an active validation")
        }
        XCTAssertEqual(requestCount.currentValue(), 1)
    }

    func testActivationPersistenceFailureNotifiesFailClosedState() async throws {
        let initialState = paidState()
        let context = try makeContext(initialState: initialState)
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":true},"data":{"id":"license-new","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }
        let callback = expectation(description: "activation persistence failure callback")
        context.manager.onStatusChange = { status, allowed in
            XCTAssertEqual(status, .valid)
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let result = await context.manager.activateLicense(key: "new-key")

        guard case .error = result else {
            return XCTFail("Activation must fail when state cannot be persisted")
        }
        await fulfillment(of: [callback], timeout: 1)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.licenseKey, initialState.licenseKey)
        XCTAssertEqual(saved.machineId, initialState.machineId)
    }

    func testValidationWaitTimeoutFailsClosed() async throws {
        let context = try makeContext(
            initialState: paidState(),
            validationWaitTimeout: 0.05
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestStarted = DispatchSemaphore(value: 0)
        let releaseRequest = DispatchSemaphore(value: 0)
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            requestStarted.signal()
            _ = releaseRequest.wait(timeout: .now() + 2)
            throw URLError(.notConnectedToInternet)
        }

        let firstValidation = Task {
            await context.manager.ensureValidLicense()
        }
        XCTAssertEqual(requestStarted.wait(timeout: .now() + 1), .success)

        let timedOutAllowed = await context.manager.ensureValidLicense()
        releaseRequest.signal()
        _ = await firstValidation.value

        XCTAssertFalse(timedOutAllowed)
        XCTAssertEqual(requestCount.currentValue(), 1)
    }

    func testPolicyPersistenceFailureRollsBackStateAndFailsClosed() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 422,
                    body: Self.machineLimitBody
                )
            default:
                throw URLError(.badURL)
            }
        }
        let callback = expectation(description: "fail-closed callback")
        context.manager.onStatusChange = { status, allowed in
            XCTAssertEqual(status, .valid)
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        await fulfillment(of: [callback], timeout: 1)
        let info = await context.manager.getLicenseInfo()
        XCTAssertEqual(info.status, .valid)
        XCTAssertFalse(info.isServiceAllowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid)
    }

    func testPersistenceFailureLatchCannotBeReopenedByNetworkGrace() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let persistenceFailureAllowed = await context.manager.ensureValidLicense()
        XCTAssertFalse(persistenceFailureAllowed)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let graceAllowed = await context.manager.ensureValidLicense()
        let currentAllowed = await context.manager.isServiceAllowed()
        XCTAssertFalse(graceAllowed)
        XCTAssertFalse(currentAllowed)
    }

    /// A first launch without connectivity is not proof that the machine has no
    /// trial. Persisting `.invalid` there would disable the install forever,
    /// because the resulting state has nothing left to validate.
    func testTransientTrialRegistrationFailureRetriesWithoutPersistingAttemptState()
        async throws
    {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.notConnectedToInternet)
        }

        let firstAllowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(firstAllowed)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: context.licensePath.path),
            "A failed trial registration must not persist a verdict"
        )

        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.badServerResponse)
        }

        let secondAllowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(secondAllowed)
        XCTAssertEqual(requestCount.currentValue(), 2, "Registration must be retried")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: context.licensePath.path)
        )
    }

    /// Installs that already persisted such a state have no license reference.
    /// It cannot be validated, so trial onboarding resumes instead of latching a
    /// verdict that was never served.
    func testExistingEmptyLicenseStateResumesTrialRegistration() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            _ = requestCount.increment()
            return Self.trialCreationResponse(for: request)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(
            requestCount.currentValue(),
            3,
            "Lookup, create, then the lookup for the signed answer"
        )
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.licenseId, "trial-1")
        XCTAssertEqual(saved.status, .trial)
    }

    func testDamagedInvalidTrialStateDoesNotPersistAVerdictWhileOffline() async throws {
        let context = try makeContext(initialState: LicenseState(status: .invalid))
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertNil(saved.licenseId)
        XCTAssertEqual(saved.status, .invalid)
        XCTAssertNil(saved.lastValidatedAt)
    }

    /// An offline start outside grace must recover by itself once
    /// connectivity returns, without waiting for a resolver restart or for
    /// `NetworkMonitor` callbacks that are not accepted yet at startup.
    func testOfflineStartupOutsideGraceRetriesAndRestoresAfterNetworkRecovery()
        async throws
    {
        let expiredGrace = Date().addingTimeInterval(-(73 * 60 * 60))
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: expiredGrace),
            retryPolicy: Self.immediateRetryPolicy
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            guard requestCount.increment() > 1 else {
                throw URLError(.notConnectedToInternet)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let initiallyAllowed = await context.manager.ensureValidLicense()
        XCTAssertFalse(initiallyAllowed)

        await context.manager.waitForPendingRetry()

        let recovered = await context.manager.isServiceAllowed()
        XCTAssertTrue(recovered, "The license retry must restore service on its own")
        XCTAssertGreaterThan(requestCount.currentValue(), 1)
    }

    /// A retry that lands while a failing activation holds the license gate must
    /// not report that activation's outcome and end the loop, or an offline
    /// first run never registers its trial.
    func testOfflineTrialRetrySurvivesAFailedActivationHoldingTheGate() async throws {
        let context = try makeContext(
            retryPolicy: LicenseRetryPolicy(
                maxAttempts: 5,
                sleep: { _ in try? await Task.sleep(nanoseconds: 600_000_000) }
            )
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let activationStarted = LockedCounter()
        let online = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if activationStarted.currentValue() > 0, online.currentValue() == 0 {
                Thread.sleep(forTimeInterval: 1)
                _ = online.increment()
                throw URLError(.timedOut)
            }
            guard online.currentValue() > 0 else {
                throw URLError(.notConnectedToInternet)
            }
            return Self.trialCreationResponse(for: request)
        }

        let initiallyAllowed = await context.manager.ensureValidLicense()
        XCTAssertFalse(initiallyAllowed)

        _ = activationStarted.increment()
        let activation = await context.manager.activateLicense(key: "paid-key")
        guard case .networkError = activation else {
            return XCTFail("The activation must fail offline, got \(activation)")
        }
        await context.manager.waitForPendingRetry()

        let allowed = await context.manager.isServiceAllowed()
        XCTAssertTrue(allowed, "The retry must register the trial once online")
        XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
    }

    func testTrialPersistenceFailureDoesNotAllowServices() async throws {
        let context = try makeContext()
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { request in
            Self.trialCreationResponse(for: request)
        }
        let callback = expectation(description: "trial persistence failure callback")
        context.manager.onStatusChange = { status, allowed in
            XCTAssertEqual(status, .unknown)
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        await fulfillment(of: [callback], timeout: 1)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: context.licensePath.path)
        )
    }

    func testReactivationPersistenceFailureDoesNotRestoreService() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }
        let callback = expectation(description: "reactivation persistence failure callback")
        context.manager.onStatusChange = { status, allowed in
            XCTAssertEqual(status, .valid)
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        await fulfillment(of: [callback], timeout: 1)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.machineId, "machine-old")
    }

    func testReactivationIntentIsPersistedBeforeMachinePost() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let postObserved = expectation(description: "machine post observed")
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                let persisted = try self.savedState(at: context.licensePath)
                XCTAssertNil(persisted.machineId)
                XCTAssertEqual(persisted.machineReactivationPending, true)
                postObserved.fulfill()
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let allowed = await context.manager.ensureValidLicense()
        XCTAssertTrue(allowed)
        await fulfillment(of: [postObserved], timeout: 1)
    }

    func testReactivationIntentPersistenceFailurePreventsMachinePost() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        try FileManager.default.removeItem(at: context.licensePath)
        try FileManager.default.createDirectory(
            at: context.licensePath,
            withIntermediateDirectories: true
        )
        let machinePosts = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            }
            if request.url?.path.hasSuffix("/machines") == true {
                _ = machinePosts.increment()
            }
            throw URLError(.badURL)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertEqual(machinePosts.currentValue(), 0)
        let serviceAllowed = await context.manager.isServiceAllowed()
        XCTAssertFalse(serviceAllowed)
    }

    func testPendingReactivationIsNotAdmittedBeforeResumeAttempt() async throws {
        var pendingState = paidState()
        pendingState.machineId = nil
        pendingState.machineReactivationPending = true
        let context = try makeContext(initialState: pendingState)
        defer { try? FileManager.default.removeItem(at: context.directory) }

        let info = await context.manager.getLicenseInfo()

        XCTAssertFalse(pendingState.isActive)
        XCTAssertFalse(info.isServiceAllowed)
    }

    func testRestartResumesPendingReactivationAfterValidResponse() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            }
            throw URLError(.notConnectedToInternet)
        }

        let blockedWhilePending = await context.manager.ensureValidLicense()
        XCTAssertFalse(blockedWhilePending)
        let pending = try savedState(at: context.licensePath)
        XCTAssertNil(pending.machineId)
        XCTAssertEqual(pending.machineReactivationPending, true)

        let restartedManager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/licenses/actions/validate-key"):
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-restarted"}}"#
                )
            default:
                throw URLError(.badURL)
            }
        }

        let restoredAllowed = await restartedManager.ensureValidLicense()
        XCTAssertTrue(restoredAllowed)
        let completed = try savedState(at: context.licensePath)
        XCTAssertEqual(completed.machineId, "machine-restarted")
        XCTAssertEqual(completed.machineReactivationPending, false)
    }

    func testInitializeRestoresDurableFailClosedLatch() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(
                    reason: .networkGraceExpired,
                    engagedAt: Date()
                )
            )
        )
        let restartedManager = makeManager(licensePath: context.licensePath)

        await restartedManager.initialize()

        let allowed = await restartedManager.isServiceAllowed()
        XCTAssertFalse(allowed)
    }

    func testPaidValidationJournalSurvivesStateAndLatchPersistenceFailure() async throws {
        let context = try makeContext(initialState: paidState())
        let journalPath = context.licensePath.appendingPathExtension("admission-journal")
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o500],
                ofItemAtPath: context.directory.path
            )
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let initialAllowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(initialAllowed)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: context.directory.path
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))

        let restartedManager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let restartedAllowed = await restartedManager.ensureValidLicense()
        let restartedServiceAllowed = await restartedManager.isServiceAllowed()

        XCTAssertFalse(restartedAllowed)
        XCTAssertFalse(restartedServiceAllowed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))
    }

    func testPaidValidationDoesNotRequestWhenJournalCannotBeArmed() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()
        let serviceAllowed = await context.manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertEqual(requestCount.currentValue(), 0)
        XCTAssertFalse(serviceAllowed)
    }

    func testEarlyExitReleasesTheValidationGate() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            _ = requestCount.increment()
            return Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let blocked = await context.manager.ensureValidLicense()
        XCTAssertFalse(blocked)
        XCTAssertEqual(requestCount.currentValue(), 0)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: context.directory.path
        )

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(requestCount.currentValue(), 1)
    }

    /// Trial validation is one public, nonce-bound lookup by fingerprint, which
    /// is also the usage callhome. It carries no token and no machine scope.
    func testTrialValidationIsOneNonceBoundLookupAndPersistsServerTime() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        let serverTime = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        LicenseURLProtocolStub.handler = { request in
            _ = requestCount.increment()
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertTrue(request.url?.path.hasSuffix("/licenses/actions/validate-key") == true)
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
            let body = try XCTUnwrap(LicenseTestResponseSigner.requestBody(of: request))
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            let meta = try XCTUnwrap(json["meta"] as? [String: Any])
            XCTAssertNotNil(meta["nonce"])
            XCTAssertEqual(meta["key"] as? String, "test-fingerprint")
            XCTAssertEqual((meta["scope"] as? [String: String])?["policy"], LicenseManager.KeygenConfig.trialPolicyId)
            XCTAssertNil((meta["scope"] as? [String: String])?["fingerprint"])
            return Self.signer.response(
                for: request,
                statusCode: 200,
                body: Self.liveTrialLookupBody,
                date: serverTime
            )
        }

        let allowed = await context.manager.ensureValidLicense()
        XCTAssertTrue(allowed)
        _ = await context.manager.validateLicense()

        XCTAssertEqual(requestCount.currentValue(), 2)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertEqual(saved.lastValidatedAt, serverTime)
    }

    /// `license.json` is user-writable. A state that only claims a recent
    /// validation must not run offline, or editing the file and blocking the
    /// license API would run MacDNS forever.
    func testLicenseFileWithoutASignedValidationGetsNoOfflineGrace() async throws {
        let claimed = [
            LicenseState(
                licenseKey: "paid-key",
                licenseId: "license-1",
                machineId: "machine-old",
                status: .valid,
                lastValidatedAt: Date()
            ),
            LicenseState(licenseId: "trial-1", status: .trial, lastValidatedAt: Date()),
        ]
        for initialState in claimed {
            let context = try makeContext(initialState: initialState)
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { _ in
                throw URLError(.notConnectedToInternet)
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertFalse(allowed, "\(initialState.status)")
        }
    }

    /// The status of these licenses reads as fine, so without a reason the
    /// About tab shows a working license next to protection that is off.
    func testUnansweredLicenseCheckTellsTheUserToConnect() async throws {
        var withoutReceipt = paidState()
        withoutReceipt.validationReceipt = nil
        let unanswered = try XCTUnwrap(
            LicenseBlockReason.message(latch: nil, clockTrusted: true, checkUnanswered: true)
        )
        for initialState in [withoutReceipt, nil] {
            let context = try makeContext(initialState: initialState)
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { _ in
                throw URLError(.notConnectedToInternet)
            }

            let beforeTheCheck = await context.manager.getLicenseInfo()
            let allowed = await context.manager.ensureValidLicense()
            let afterTheCheck = await context.manager.getLicenseInfo()

            let label = "\(String(describing: initialState?.status))"
            XCTAssertNil(beforeTheCheck.blockReason, label)
            XCTAssertFalse(allowed, label)
            XCTAssertEqual(afterTheCheck.blockReason, unanswered, label)
        }
    }

    /// An ended trial explains itself. Connecting would not bring it back.
    func testUnansweredCheckOfAnEndedTrialGivesNoConnectionAdvice() async throws {
        let context = try makeContext(
            initialState: LicenseState(licenseId: "trial-1", status: .trialExpired)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in throw URLError(.notConnectedToInternet) }

        let allowed = await context.manager.ensureValidLicense()
        let info = await context.manager.getLicenseInfo()

        XCTAssertFalse(allowed)
        XCTAssertNil(info.blockReason)
    }

    func testValidationStoresTheSignedAnswerTheNextOfflineStartRunsOn() async throws {
        // A license saved by a version that stored no signed answer.
        var withoutReceipt = paidState()
        withoutReceipt.validationReceipt = nil
        let context = try makeContext(initialState: withoutReceipt)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            Self.response(for: request, statusCode: 200, body: Self.validPaidValidationBody)
        }

        let online = await context.manager.ensureValidLicense()

        XCTAssertTrue(online)
        XCTAssertNotNil(try savedState(at: context.licensePath).validationReceipt)

        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        let offline = await makeManager(licensePath: context.licensePath)
            .ensureValidLicense()

        XCTAssertTrue(offline)
    }

    /// The create answer is no receipt. Without the lookup that follows it, a
    /// new trial would stop at its first validation without network.
    func testNewTrialStoresASignedAnswerTheNextOfflineStartRunsOn() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let created = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) {
                _ = created.increment()
                return Self.trialCreationResponse(for: request)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: created.currentValue() == 0
                    ? Self.unknownTrialLookupBody : Self.liveTrialLookupBody
            )
        }

        let online = await context.manager.ensureValidLicense()

        XCTAssertTrue(online)
        XCTAssertEqual(created.currentValue(), 1)
        XCTAssertNotNil(try savedState(at: context.licensePath).validationReceipt)

        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        let offline = await makeManager(licensePath: context.licensePath)
            .ensureValidLicense()

        XCTAssertTrue(offline)
    }

    /// The machine answer is no receipt either, so the key is validated again
    /// once the seat exists.
    func testActivationStoresASignedAnswerTheNextOfflineStartRunsOn() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let activated = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/machines") == true {
                _ = activated.increment()
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-1"}}"#
                )
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: activated.currentValue() == 0
                    ? Self.noMachineValidationBody : Self.validPaidValidationBody
            )
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .success = result else {
            return XCTFail("Activation must succeed, got \(result)")
        }
        XCTAssertNotNil(try savedState(at: context.licensePath).validationReceipt)

        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        let offline = await makeManager(licensePath: context.licensePath)
            .ensureValidLicense()

        XCTAssertTrue(offline)
    }

    /// The state rests on the validation that follows the activation, so the
    /// expiry comes from that answer too. A license renewed between the two
    /// answers runs on its new date at once, on activation, on an activation
    /// of a seat that already existed and on a reactivation.
    func testExpiryComesFromTheAnswerTheSeatRestsOn() async throws {
        let renewedExpiry = try XCTUnwrap(ISO8601DateFormatter().date(from: "2031-01-01T00:00:00Z"))
        for seatExists in [false, true] {
            for reactivation in [false, true] {
                let label = "seatExists: \(seatExists), reactivation: \(reactivation)"
                let context = try makeContext(initialState: reactivation ? paidState() : nil)
                defer { try? FileManager.default.removeItem(at: context.directory) }
                let activated = LockedCounter()
                LicenseURLProtocolStub.handler = { request in
                    switch (request.httpMethod, request.url?.path) {
                    case ("POST", let path?) where path.hasSuffix("/machines"):
                        _ = activated.increment()
                        return seatExists
                            ? Self.response(
                                for: request, statusCode: 422, body: Self.fingerprintTakenBody)
                            : Self.response(
                                for: request, statusCode: 201,
                                body: #"{"data":{"id":"machine-1"}}"#)
                    case ("GET", let path?) where path.hasSuffix("/machines"):
                        return Self.response(
                            for: request, statusCode: 200,
                            body: #"{"data":[{"id":"machine-1"}]}"#)
                    default:
                        return Self.response(
                            for: request, statusCode: 200,
                            body: activated.currentValue() == 0
                                ? Self.noMachineValidationBody : Self.renewedPaidValidationBody)
                    }
                }

                if reactivation {
                    let allowed = await context.manager.ensureValidLicense()
                    XCTAssertTrue(allowed, label)
                } else {
                    let result = await context.manager.activateLicense(key: "paid-key")
                    switch result {
                    case .success, .alreadyActivated: break
                    default: XCTFail("Activation must succeed, got \(result) (\(label))")
                    }
                }

                XCTAssertEqual(activated.currentValue(), 1, label)
                XCTAssertEqual(try savedState(at: context.licensePath).expiresAt, renewedExpiry, label)
            }
        }
    }

    /// The App waits `LicenseRequestBudget.operation` for a license answer,
    /// which counts `maxRequestsPerOperation` requests in a row and
    /// `maxIdentityReadsPerOperation` hardware reads. No operation may send or
    /// read more: a new trial, a trial whose key is taken, a stored trial that
    /// Keygen no longer has, and an activation or a reactivation of a seat
    /// that already exists.
    func testNoLicenseOperationExceedsTheBudget() async throws {
        let budget = LicenseRequestBudget.maxRequestsPerOperation
        let readBudget = LicenseRequestBudget.maxIdentityReadsPerOperation
        let trialCases: [(state: LicenseState?, keyTaken: Bool, label: String)] = [
            (nil, false, "new trial"),
            (nil, true, "key taken"),
            (activeTrialState(), false, "stored trial gone"),
        ]

        for (initialState, keyTaken, label) in trialCases {
            let reads = LockedCounter()
            let context = try makeContext(
                initialState: initialState,
                fingerprintProvider: {
                    _ = reads.increment()
                    return "test-fingerprint"
                }
            )
            defer { try? FileManager.default.removeItem(at: context.directory) }
            let requests = LockedCounter()
            let created = LockedCounter()
            LicenseURLProtocolStub.handler = { request in
                _ = requests.increment()
                if Self.isTrialCreate(request) {
                    _ = created.increment()
                    return keyTaken
                        ? Self.response(for: request, statusCode: 422, body: Self.keyTakenBody)
                        : Self.trialCreationResponse(for: request)
                }
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: created.currentValue() == 0
                        ? Self.unknownTrialLookupBody : Self.liveTrialLookupBody
                )
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertTrue(allowed, label)
            XCTAssertLessThanOrEqual(requests.currentValue(), budget, label)
            XCTAssertLessThanOrEqual(reads.currentValue(), readBudget, label)
        }

        for reactivation in [false, true] {
            let reads = LockedCounter()
            let context = try makeContext(
                initialState: reactivation ? paidState() : nil,
                fingerprintProvider: {
                    _ = reads.increment()
                    return "test-fingerprint"
                }
            )
            defer { try? FileManager.default.removeItem(at: context.directory) }
            let requests = LockedCounter()
            let activated = LockedCounter()
            LicenseURLProtocolStub.handler = { request in
                _ = requests.increment()
                switch (request.httpMethod, request.url?.path) {
                case ("POST", let path?) where path.hasSuffix("/machines"):
                    _ = activated.increment()
                    return Self.response(
                        for: request, statusCode: 422, body: Self.fingerprintTakenBody)
                case ("GET", let path?) where path.hasSuffix("/machines"):
                    return Self.response(
                        for: request, statusCode: 200, body: #"{"data":[{"id":"machine-1"}]}"#)
                default:
                    return Self.response(
                        for: request,
                        statusCode: 200,
                        body: activated.currentValue() == 0
                            ? Self.noMachineValidationBody : Self.validPaidValidationBody
                    )
                }
            }

            if reactivation {
                let allowed = await context.manager.ensureValidLicense()
                XCTAssertTrue(allowed)
            } else {
                let result = await context.manager.activateLicense(key: "paid-key")
                guard case .alreadyActivated = result else {
                    return XCTFail("Activation must find the seat, got \(result)")
                }
            }

            XCTAssertLessThanOrEqual(requests.currentValue(), budget, "reactivation: \(reactivation)")
            XCTAssertLessThanOrEqual(reads.currentValue(), readBudget, "reactivation: \(reactivation)")
        }
    }

    /// On a Mac without a serial number one hardware read samples the hardware
    /// several times, a second apart.
    func testLocalWorkCoversTheSlowestHardwareReads() {
        let slowestRead =
            TimeInterval(MachineFingerprintPolicy.serialAbsenceSamples - 1)
            * MachineFingerprintPolicy.serialAbsenceSampleInterval

        XCTAssertGreaterThan(
            LicenseRequestBudget.localWork,
            TimeInterval(LicenseRequestBudget.maxIdentityReadsPerOperation) * slowestRead
        )
    }

    /// A periodic check that finds another license operation running is
    /// skipped. When that operation ends without a verdict, such as an
    /// activation of another key that got no answer, nothing else checks the
    /// license again, so the skip must leave a retry behind.
    func testSkippedValidationLeavesARetry() async throws {
        let activationDone = LockedCounter()
        let context = try makeContext(
            initialState: paidState(),
            retryPolicy: LicenseRetryPolicy(
                baseDelay: 0,
                maxAttempts: 3,
                sleep: { _ in
                    for _ in 0..<200 where activationDone.currentValue() == 0 {
                        try? await Task.sleep(nanoseconds: 10_000_000)
                    }
                }
            )
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        let activationStarted = DispatchSemaphore(value: 0)
        let releaseActivation = DispatchSemaphore(value: 0)
        let requests = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            guard requests.increment() > 1 else {
                activationStarted.signal()
                _ = releaseActivation.wait(timeout: .now() + 2)
                throw URLError(.notConnectedToInternet)
            }
            return Self.response(for: request, statusCode: 200, body: Self.validPaidAnswerBody)
        }

        let activation = Task { await context.manager.activateLicense(key: "other-key") }
        XCTAssertEqual(activationStarted.wait(timeout: .now() + 1), .success)
        _ = await context.manager.validateLicense()
        releaseActivation.signal()
        _ = await activation.value
        _ = activationDone.increment()
        await context.manager.waitForPendingRetry()

        XCTAssertGreaterThan(requests.currentValue(), 1, "the skipped check must run later")
    }

    /// Only a check that persists clears the fail-closed latch, and only the
    /// retry runs one on its own, so a disk that refused a write must leave a
    /// retry behind.
    func testLicenseRecoversOnItsOwnAfterTheDiskRefusedAWrite() async throws {
        let diskFixed = LockedCounter()
        let context = try makeContext(
            initialState: paidState(),
            retryPolicy: LicenseRetryPolicy(
                baseDelay: 0,
                maxAttempts: 3,
                sleep: { _ in
                    for _ in 0..<200 where diskFixed.currentValue() == 0 {
                        try? await Task.sleep(nanoseconds: 10_000_000)
                    }
                }
            )
        )
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: context.directory.path)
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            Self.response(for: request, statusCode: 200, body: Self.validPaidAnswerBody)
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500], ofItemAtPath: context.directory.path)

        let allowedWhileReadOnly = await context.manager.ensureValidLicense()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: context.directory.path)
        _ = diskFixed.increment()
        await context.manager.waitForPendingRetry()

        XCTAssertFalse(allowedWhileReadOnly)
        let recovered = await context.manager.isServiceAllowed()
        XCTAssertTrue(recovered)
    }

    /// Entering the key that already runs validates it, finds its seat taken
    /// and validates again. When that last answer is lost, the valid answer
    /// from the start of the same activation is the receipt, so the license
    /// keeps its offline grace.
    func testActivatingTheRunningKeyKeepsAReceiptWhenTheLastAnswerIsLost() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let validations = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("POST", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request, statusCode: 422, body: Self.fingerprintTakenBody)
            case ("GET", let path?) where path.hasSuffix("/machines"):
                return Self.response(
                    for: request, statusCode: 200, body: #"{"data":[{"id":"machine-old"}]}"#)
            default:
                guard validations.increment() == 1 else {
                    throw URLError(.timedOut)
                }
                return Self.response(
                    for: request, statusCode: 200, body: Self.validPaidAnswerBody)
            }
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .alreadyActivated = result else {
            return XCTFail("Activation must find the seat, got \(result)")
        }
        XCTAssertEqual(validations.currentValue(), 2)
        XCTAssertNotNil(try savedState(at: context.licensePath).validationReceipt)
        LicenseURLProtocolStub.handler = { _ in throw URLError(.notConnectedToInternet) }
        let offline = await makeManager(licensePath: context.licensePath).ensureValidLicense()
        XCTAssertTrue(offline)
    }

    /// Keygen says the seat is taken and then lists no machine for it. The
    /// two answers contradict each other, so neither is a verdict on the
    /// license: it stays, waiting for its seat, and the retry asks again.
    func testSeatTakenWithNoMachineListedIsNoVerdict() async throws {
        for conflictStatus in [409, 422] {
            let context = try makeContext(initialState: paidState())
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { request in
                switch (request.httpMethod, request.url?.path) {
                case ("POST", let path?) where path.hasSuffix("/machines"):
                    return Self.response(
                        for: request, statusCode: conflictStatus,
                        body: conflictStatus == 422
                            ? Self.fingerprintTakenBody : #"{"errors":[]}"#)
                case ("GET", let path?) where path.hasSuffix("/machines"):
                    return Self.response(for: request, statusCode: 200, body: #"{"data":[]}"#)
                default:
                    return Self.response(
                        for: request, statusCode: 200, body: Self.noMachineValidationBody)
                }
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertFalse(allowed, "\(conflictStatus)")
            let saved = try savedState(at: context.licensePath)
            XCTAssertEqual(saved.status, .valid, "\(conflictStatus)")
            XCTAssertEqual(saved.machineReactivationPending, true, "\(conflictStatus)")
        }
    }

    /// A request that has not finished within its share of the budget fails,
    /// however slowly the bytes arrive.
    func testLicenseSessionEndsEveryRequestWithinItsBudget() {
        let configuration = LicenseManager.makeLicenseSession().configuration

        XCTAssertEqual(configuration.timeoutIntervalForResource, LicenseRequestBudget.perRequest)
        XCTAssertLessThanOrEqual(
            configuration.timeoutIntervalForRequest, LicenseRequestBudget.perRequest)
    }

    /// Once the seat exists the key is validated again for a receipt. A signed
    /// rejection in that answer decides, as in any validation.
    func testRejectionAfterReactivatingTheMachineBlocksService() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let activated = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/machines") == true {
                _ = activated.increment()
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-new"}}"#
                )
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: activated.currentValue() == 0
                    ? Self.noMachineValidationBody : Self.suspendedPaidValidationBody
            )
        }

        let allowed = await context.manager.ensureValidLicense()
        let serviceAllowed = await context.manager.isServiceAllowed()

        XCTAssertEqual(activated.currentValue(), 1)
        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
        XCTAssertEqual(try savedState(at: context.licensePath).status, .invalid)
    }

    /// A key that Keygen rejects right after the seat was created is reported
    /// like a key rejected at once, and the running trial stays.
    func testRejectionAfterActivatingTheMachineKeepsTheTrial() async throws {
        let initialState = activeTrialState()
        let context = try makeContext(initialState: initialState)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        let activated = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/machines") == true {
                _ = activated.increment()
                return Self.response(
                    for: request,
                    statusCode: 201,
                    body: #"{"data":{"id":"machine-1"}}"#
                )
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: activated.currentValue() == 0
                    ? Self.noMachineValidationBody : Self.expiredPaidValidationBody
            )
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .error(let message) = result else {
            return XCTFail("An expired key must report an error, got \(result)")
        }
        XCTAssertEqual(message, "License has expired")
        XCTAssertEqual(activated.currentValue(), 1)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, initialState.status)
        XCTAssertNil(saved.licenseKey)
        XCTAssertEqual(saved.licenseId, initialState.licenseId)
    }

    /// The new trial is looked up once for a receipt. A lookup that finds it
    /// ended is the verdict.
    func testNewTrialThatTheLookupFindsEndedIsNotAdopted() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let created = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) {
                _ = created.increment()
                return Self.trialCreationResponse(for: request)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body: created.currentValue() == 0
                    ? Self.unknownTrialLookupBody : Self.endedTrialLookupBody
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertEqual(created.currentValue(), 1)
        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trialExpired)
        XCTAssertEqual(saved.licenseId, "trial-1")
    }

    /// A signed answer copied from a Mac that holds a seat, or from a Mac with
    /// a live trial, must not run this one.
    func testSignedAnswerOfAnotherMachineGetsNoOfflineGrace() async throws {
        var paid = paidState()
        paid.validationReceipt = Self.signer.receipt(
            body: Self.donorPaidAnswerBody,
            date: Date()
        )
        var trial = activeTrialState()
        trial.validationReceipt = Self.signer.receipt(
            body: Self.donorTrialLookupBody,
            date: Date()
        )
        for initialState in [paid, trial] {
            let context = try makeContext(initialState: initialState)
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { _ in
                throw URLError(.notConnectedToInternet)
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertFalse(allowed, "\(initialState.status)")
        }
    }

    /// Grace counts from the signed date, not from the time the file claims.
    func testClaimedValidationTimeCannotExtendAnOldSignedAnswer() async throws {
        var state = paidState(lastValidatedAt: Date().addingTimeInterval(-(73 * 60 * 60)))
        state.lastValidatedAt = Date()
        let context = try makeContext(initialState: state)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
    }

    /// With the trusted-time file deleted the mark is rebuilt from the time
    /// `license.json` claims. The signed date still says the clock went back.
    func testClockSetBehindTheSignedAnswerBlocksGrace() async throws {
        let signedAt = Date()
        var state = paidState(lastValidatedAt: signedAt)
        state.lastValidatedAt = signedAt.addingTimeInterval(-2 * 86_400)
        let context = try makeContext(
            initialState: state,
            wallClock: { signedAt.addingTimeInterval(-86_400) }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
    }

    /// The verdict that ends a license replaces the stored answer, so setting
    /// the status back by hand does not bring the earlier answer back.
    func testRevokedLicenseCannotRunOfflineOnItsEarlierSignedAnswer() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"license-1","attributes":{"key":"paid-key"}}}"#
            )
        }

        let revoked = await context.manager.ensureValidLicense()

        XCTAssertFalse(revoked)
        var edited = try savedState(at: context.licensePath)
        XCTAssertEqual(edited.status, .invalid)
        edited.status = .valid
        try JSONCoding.encoder.encode(edited).write(to: context.licensePath, options: .atomic)

        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        let offline = await makeManager(licensePath: context.licensePath)
            .ensureValidLicense()

        XCTAssertFalse(offline)
    }

    func testTrialLookupFailureFallsBackToGrace() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let attempts = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = attempts.increment()
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(attempts.currentValue(), 1)
        XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
    }

    func testTrialValidationJournalSurvivesStateAndLatchPersistenceFailure() async throws {
        let context = try makeContext(initialState: activeTrialState())
        let journalPath = context.licensePath.appendingPathExtension("admission-journal")
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            XCTAssertTrue(request.url?.path.hasSuffix("/licenses/actions/validate-key") == true)
            XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o500],
                ofItemAtPath: context.directory.path
            )
            return Self.response(
                for: request,
                statusCode: 200,
                body: Self.endedTrialLookupBody
            )
        }

        let initialAllowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(initialAllowed)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: context.directory.path
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))

        let restartedManager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let restartedAllowed = await restartedManager.ensureValidLicense()
        let restartedServiceAllowed = await restartedManager.isServiceAllowed()

        XCTAssertFalse(restartedAllowed)
        XCTAssertFalse(restartedServiceAllowed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath.path))
    }

    func testTrialValidationDoesNotRequestWhenJournalCannotBeArmed() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500],
            ofItemAtPath: context.directory.path
        )
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()
        let serviceAllowed = await context.manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertEqual(requestCount.currentValue(), 0)
        XCTAssertFalse(serviceAllowed)
    }

    func testValidationCallbackCanRestoreServicesWithoutHoldingValidationGate() async throws {
        let context = try makeContext(
            initialState: paidState(),
            validationWaitTimeout: 0.05
        )
        defer {
            try? FileManager.default.removeItem(at: context.directory)
        }
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }
        let restoreCompleted = expectation(description: "license callback restore completed")
        context.manager.onStatusChange = { _, allowed in
            guard allowed else { return }
            Task {
                let restored = await context.manager.ensureValidLicense()
                XCTAssertTrue(restored)
                restoreCompleted.fulfill()
            }
        }

        _ = await context.manager.validateLicense()
        await fulfillment(of: [restoreCompleted], timeout: 1)
    }

    func testFailedLatchClearKeepsSuccessfulValidationFailClosed() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        try FileManager.default.createDirectory(
            at: store.failClosedPath,
            withIntermediateDirectories: true
        )
        let restartedManager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let allowed = await restartedManager.ensureValidLicense()
        let serviceAllowed = await restartedManager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
    }

    func testDeactivationFinalPersistenceFailureKeepsDurablePendingState() async throws {
        let context = try makeContext(initialState: paidState())
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: context.directory.path
            )
            try? FileManager.default.removeItem(at: context.directory)
        }
        await context.manager.initialize()
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            guard request.httpMethod == "DELETE" else {
                throw URLError(.badURL)
            }
            _ = requestCount.increment()
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o500],
                ofItemAtPath: context.directory.path
            )
            return Self.response(
                for: request,
                statusCode: 204,
                body: ""
            )
        }

        let deactivated = await context.manager.deactivateLicense()

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: context.directory.path
        )
        XCTAssertFalse(deactivated)
        XCTAssertEqual(requestCount.currentValue(), 1)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.deactivationPending, true)
        XCTAssertEqual(saved.machineId, "machine-old")
        XCTAssertEqual(saved.status, .invalid)
    }

    func testPendingDeactivationCompletesWithoutMachineReactivation() async throws {
        var pendingState = paidState()
        pendingState.status = .invalid
        pendingState.deactivationPending = true
        let context = try makeContext(initialState: pendingState)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            guard request.httpMethod == "DELETE" else {
                throw URLError(.badURL)
            }
            return Self.response(
                for: request,
                statusCode: 404,
                body: ""
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.deactivationPending, false)
        XCTAssertNil(saved.licenseKey)
        XCTAssertNil(saved.machineId)
        XCTAssertEqual(saved.status, .trialExpired)
    }

    // MARK: - Response provenance

    private static func isFailClosedEngaged(_ store: LicenseStateFileStore) -> Bool {
        if case .loaded = store.loadFailClosedState() { return true }
        return false
    }

    /// A forged verdict must never reach durable state. Otherwise a trusted
    /// local or corporate CA plus DNS redirection can disable a paid license
    /// permanently.
    func testUnsignedRejectionCannotChangeDurableStatus() async throws {
        let lastValidatedAt = Date().addingTimeInterval(-60)
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: lastValidatedAt)
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            LicenseTestResponseSigner.unsignedResponse(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"license-1"}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed, "An unverified response falls back to bounded grace")
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid)
        XCTAssertEqual(saved.lastValidatedAt, lastValidatedAt)
    }

    /// The mirror image: a forged *valid* response must not unlock a machine.
    func testUnsignedApprovalCannotClearFailClosedLatch() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(reason: .networkGraceExpired, engagedAt: Date())
            )
        )
        let manager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            LicenseTestResponseSigner.unsignedResponse(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let allowed = await manager.ensureValidLicense()
        let serviceAllowed = await manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
        XCTAssertTrue(Self.isFailClosedEngaged(store))
    }

    /// Proves the previous test is not vacuous: verified evidence does clear the
    /// latch.
    func testSignedApprovalClearsFailClosedLatch() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(reason: .networkGraceExpired, engagedAt: Date())
            )
        )
        let manager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let allowed = await manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertFalse(Self.isFailClosedEngaged(store))
    }

    /// An empty local state must not reach the authoritative path with no
    /// request at all, which would clear the latch without server evidence.
    func testEmptyStateWithoutServerEvidenceCannotClearFailClosedLatch() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(reason: .stateLoadFailed, engagedAt: Date())
            )
        )
        let manager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertTrue(Self.isFailClosedEngaged(store))
    }

    /// Keygen reports real rejections as 200 +
    /// `meta.valid`, so a 4xx is an availability problem and must not be
    /// persisted as a terminal verdict.
    func testClientErrorStatusesDoNotPersistATerminalVerdict() async throws {
        for statusCode in [401, 403, 404, 407] {
            let lastValidatedAt = Date(
                timeIntervalSince1970: floor(Date().timeIntervalSince1970) - 60
            )
            let context = try makeContext(
                initialState: paidState(lastValidatedAt: lastValidatedAt)
            )
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { request in
                Self.response(for: request, statusCode: statusCode, body: "")
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertTrue(allowed, "HTTP \(statusCode) must stay within grace")
            let saved = try savedState(at: context.licensePath)
            XCTAssertEqual(saved.status, .valid, "HTTP \(statusCode)")
            XCTAssertEqual(saved.lastValidatedAt, lastValidatedAt)
        }
    }

    // MARK: - Trusted clock

    /// A clock rolled back behind verified server time must block instead of
    /// regaining a fresh 72h grace window.
    func testClockRollbackBlocksGraceInsteadOfExtendingIt() async throws {
        let realNow = Date()
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: realNow.addingTimeInterval(-60)),
            wallClock: { realNow.addingTimeInterval(-(30 * 24 * 60 * 60)) }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveTrustedTimeMark(LicenseTrustedTimeMark(serverTime: realNow))
        )
        LicenseURLProtocolStub.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed, "A rolled-back clock must never grant grace")
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid, "and must never persist a terminal verdict")
    }

    /// A recorded answer carries the nonce of the request it was recorded for,
    /// so it cannot satisfy a fresh lookup even though it is correctly signed.
    /// A wall clock rolled back behind verified server time must not make the
    /// recorded verdict fresh or clear the fail-closed latch.
    func testReplayedTrialLookupUnderRolledBackClockIsRefused() async throws {
        let capturedAt = Date()
        let context = try makeContext(
            initialState: activeTrialState(
                lastValidatedAt: capturedAt.addingTimeInterval(-60)
            )
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        // Verified server time already seen is far ahead of the wall clock.
        XCTAssertTrue(
            store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(
                    serverTime: capturedAt.addingTimeInterval(30 * 24 * 60 * 60)
                )
            )
        )
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(
                    reason: .networkGraceExpired,
                    engagedAt: capturedAt
                )
            )
        )
        let manager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            let recorded = Data(
                #"{"meta":{"valid":false,"code":"NO_MACHINES","nonce":1},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"test-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
                    .utf8
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: Self.signer.headers(
                    for: request,
                    body: recorded,
                    date: capturedAt
                )
            )!
            return (response, recorded)
        }

        let allowed = await manager.ensureValidLicense()
        let serviceAllowed = await manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
        XCTAssertTrue(Self.isFailClosedEngaged(store))
    }

    /// The trusted-time high-water mark is part of the authoritative transition:
    /// if it cannot be persisted the latch must stay engaged, otherwise the next
    /// rollback re-admits this very state.
    func testUnpersistableTrustedTimeKeepsFailClosedLatchEngaged() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(
                    reason: .networkGraceExpired,
                    engagedAt: Date()
                )
            )
        )
        try FileManager.default.createDirectory(
            at: store.trustedTimePath,
            withIntermediateDirectories: true
        )
        let manager = makeManager(licensePath: context.licensePath)
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body: #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
            )
        }

        let allowed = await manager.ensureValidLicense()
        let serviceAllowed = await manager.isServiceAllowed()

        XCTAssertFalse(allowed)
        XCTAssertFalse(serviceAllowed)
        XCTAssertTrue(Self.isFailClosedEngaged(store))
    }

    // MARK: - Machine fingerprint

    /// `license.json` is user-writable. A fingerprint read back from it would
    /// let anyone mint a new trial by editing the field, so the identity always
    /// comes from the hardware and is never written.
    func testFingerprintStoredInTheLicenseFileIsIgnored() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try Data(
            #"{"status":"unknown","machineFingerprint":"forged","machineFingerprintVersion":1}"#.utf8
        ).write(to: context.licensePath)
        let sentKeys = LockedFingerprints()
        LicenseURLProtocolStub.handler = { request in
            if let body = LicenseTestResponseSigner.requestBody(of: request),
                let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                let meta = json["meta"] as? [String: Any],
                let key = meta["key"] as? String
            {
                sentKeys.append(key)
            }
            return Self.response(for: request, statusCode: 200, body: Self.liveTrialLookupBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(sentKeys.values(), ["test-fingerprint"])
        let saved = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: context.licensePath))
                as? [String: Any]
        )
        XCTAssertNil(saved["machineFingerprint"])
        XCTAssertNil(saved["machineFingerprintVersion"])
    }

    func testMissingFingerprintOnAFreshInstallBlocksWithoutPersistingAVerdict()
        async throws
    {
        let context = try makeContext(fingerprintProvider: { nil })
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.badURL)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertEqual(requestCount.currentValue(), 0)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: context.licensePath.path)
        )
    }

    // MARK: - Trial resolution

    /// A create whose response was lost (timeout, agent killed) leaves Keygen
    /// holding the trial. The retry gets `KEY_TAKEN`, which must adopt that
    /// trial instead of persisting `.trialExpired` and killing it.
    func testKeyTakenAdoptsTheTrialKeygenAlreadyHolds() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let lookups = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                let body =
                    lookups.increment() == 1
                    ? Self.unknownTrialLookupBody : Self.liveTrialLookupBody
                return Self.response(for: request, statusCode: 200, body: body)
            }
            XCTAssertTrue(Self.isTrialCreate(request))
            return Self.response(for: request, statusCode: 422, body: Self.keyTakenBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertEqual(saved.licenseId, "trial-1")
        XCTAssertEqual(saved.expiresAt, Date(timeIntervalSince1970: 1_893_456_000))
    }

    func testReinstallDuringActiveTrialAdoptsItWithoutCreatingAnother() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            XCTAssertTrue(Self.isTrialLookup(request), "No trial may be created")
            return Self.response(for: request, statusCode: 200, body: Self.liveTrialLookupBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertEqual(saved.licenseId, "trial-1")
    }

    /// The ended trial keeps its reference, so later starts look it up instead of
    /// posting a create on every Enable.
    func testEndedTrialKeepsItsReferenceAndIsNeverCreatedAgain() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let creates = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) { _ = creates.increment() }
            return Self.response(for: request, statusCode: 200, body: Self.endedTrialLookupBody)
        }

        let firstAllowed = await context.manager.ensureValidLicense()
        let secondAllowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(firstAllowed)
        XCTAssertFalse(secondAllowed)
        XCTAssertEqual(creates.currentValue(), 0)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trialExpired)
        XCTAssertEqual(saved.licenseId, "trial-1")
    }

    /// Keygen signs the response, not the request. A signed answer about another
    /// machine's trial must never become this machine's license.
    func testTrialLookupAboutAnotherMachinePersistsNothing() async throws {
        let context = try makeContext(retryPolicy: Self.disabledRetryPolicy)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let creates = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) { _ = creates.increment() }
            return Self.response(for: request, statusCode: 200, body: Self.donorTrialLookupBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertEqual(creates.currentValue(), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: context.licensePath.path))
    }

    func testTrialCreatedForAnotherMachinePersistsNothing() async throws {
        let context = try makeContext(retryPolicy: Self.disabledRetryPolicy)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                return Self.response(for: request, statusCode: 200, body: Self.unknownTrialLookupBody)
            }
            return Self.response(
                for: request,
                statusCode: 201,
                body:
                    #"{"data":{"id":"donor-trial","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"donor-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: context.licensePath.path))
    }

    /// Only the structured `KEY_TAKEN` code means the trial exists. Any other
    /// rejection, even one whose text mentions a key, is not a verdict.
    func testUnrecognizedTrialRejectionPersistsNothing() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                return Self.response(for: request, statusCode: 200, body: Self.unknownTrialLookupBody)
            }
            return Self.response(
                for: request,
                statusCode: 422,
                body:
                    #"{"errors":[{"title":"Unprocessable resource","detail":"key is too short","code":"KEY_TOO_SHORT","source":{"pointer":"/data/attributes/key"}}]}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: context.licensePath.path))
    }

    func testKeyTakenWithoutAFindableTrialPersistsNothing() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                return Self.response(for: request, statusCode: 200, body: Self.unknownTrialLookupBody)
            }
            return Self.response(for: request, statusCode: 422, body: Self.keyTakenBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: context.licensePath.path))
    }

    /// Support resets a trial by deleting the license on Keygen. The verified
    /// `NOT_FOUND` drops the stale reference and the machine registers again.
    func testTrialDeletedOnTheServerIsRegisteredAgain() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                return Self.response(for: request, statusCode: 200, body: Self.unknownTrialLookupBody)
            }
            return Self.response(
                for: request,
                statusCode: 201,
                body:
                    #"{"data":{"id":"trial-2","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"test-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertEqual(saved.licenseId, "trial-2")
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: context.licensePath.appendingPathExtension("admission-journal").path
            )
        )
    }

    // MARK: - Machine activation rejections

    /// Keygen's real limit detail never contains the word "limit", so matching
    /// on the text reported a full license as a generic error.
    func testMachineLimitIsReadFromTheErrorCode() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: Self.noMachineValidationBody
                )
            }
            return Self.response(
                for: request,
                statusCode: 422,
                body:
                    #"{"errors":[{"title":"Unprocessable resource","detail":"machine count has exceeded maximum allowed for license (3)","code":"MACHINE_LIMIT_EXCEEDED","source":{"pointer":"/data"}}]}"#
            )
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .machineLimit(let limit) = result else {
            return XCTFail("Expected machineLimit, got \(result)")
        }
        XCTAssertEqual(limit, 3)
    }

    func testUnrecognizedMachineRejectionFailsActivationWithoutPersisting() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: Self.noMachineValidationBody
                )
            }
            return Self.response(for: request, statusCode: 422, body: Self.unknownMachineRejectionBody)
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .error = result else {
            return XCTFail("Expected error, got \(result)")
        }
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertNil(saved.licenseKey)
    }

    /// An unknown rejection is not a verdict on the seat. Reactivation must stay
    /// pending and retry instead of marking a paid license invalid.
    func testUnrecognizedMachineRejectionDoesNotInvalidateAPaidLicense() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body: Self.noMachineValidationBody
                )
            }
            return Self.response(for: request, statusCode: 422, body: Self.unknownMachineRejectionBody)
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid)
        XCTAssertEqual(saved.machineReactivationPending, true)
    }

    // MARK: - Refresh

    /// Refresh is what a user presses when the trial never appeared, so it must
    /// run the same resolution as Enable instead of reporting "nothing to check".
    func testRefreshRegistersTheMissingTrial() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            Self.trialCreationResponse(for: request)
        }

        let info = await context.manager.validateLicense()

        XCTAssertEqual(info.status, .trial)
        XCTAssertTrue(info.isServiceAllowed)
        XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
    }

    /// The trial is created with the token the build injected, the only
    /// request that sends one.
    func testTrialCreationSendsTheBuildToken() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let createAuthorization = LockedValue<String?>(nil)
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) {
                createAuthorization.set(request.value(forHTTPHeaderField: "Authorization"))
            }
            return Self.trialCreationResponse(for: request)
        }

        _ = await context.manager.validateLicense()

        XCTAssertEqual(createAuthorization.get(), "Bearer \(Self.testTrialToken)")
    }

    /// A build without a trial token never sends a create request and stays
    /// without a trial, so a dev build cannot mint trials.
    func testABuildWithoutATrialTokenNeverCreatesATrial() async throws {
        let context = try makeContext(initialState: LicenseState(), trialToken: nil)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let creates = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) {
                _ = creates.increment()
            }
            return Self.trialCreationResponse(for: request)
        }

        let info = await context.manager.validateLicense()

        XCTAssertEqual(creates.currentValue(), 0)
        XCTAssertNotEqual(info.status, .trial)
        XCTAssertFalse(info.isServiceAllowed)
    }

    // MARK: - Block reason

    func testCorruptLicenseFileReportsWhyServiceIsBlocked() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try Data("{ not json".utf8).write(to: context.licensePath)

        let info = await context.manager.getLicenseInfo()

        XCTAssertFalse(info.isServiceAllowed)
        XCTAssertEqual(
            info.blockReason,
            LicenseBlockReason.message(latch: .stateLoadFailed, clockTrusted: true)
        )
    }

    /// An activation interrupted before any license reference was saved leaves
    /// its journal behind. The verified trial adoption that follows must finish
    /// it, otherwise the latch can never clear and the Mac stays blocked.
    func testVerifiedTrialAdoptionFinishesAnInterruptedOperation() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let store = LicenseStateFileStore(path: context.licensePath)
        XCTAssertTrue(store.saveAdmissionJournal(LicenseAdmissionJournalEntry(armedAt: Date())))
        LicenseURLProtocolStub.handler = { request in
            Self.response(for: request, statusCode: 200, body: Self.liveTrialLookupBody)
        }

        let blocked = await context.manager.getLicenseInfo()
        XCTAssertEqual(
            blocked.blockReason,
            LicenseBlockReason.message(
                latch: .statePersistenceFailed,
                clockTrusted: true,
                operationInterrupted: true
            )
        )

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: context.licensePath.appendingPathExtension("admission-journal").path
            )
        )
    }

    /// The signed answer is tied to this Mac, and a Mac whose hardware identity
    /// cannot be read cannot show it is that Mac. Nothing is latched, so the
    /// first check that reads the hardware runs on the same answer.
    func testUnreadableHardwareIdentityGetsNoOfflineGraceUntilItIsReadAgain() async throws {
        for initialState in [paidState(), activeTrialState()] {
            let successfulReads = LockedCounter()
            let context = try makeContext(
                initialState: initialState,
                fingerprintProvider: {
                    successfulReads.currentValue() > 0 ? "test-fingerprint" : nil
                }
            )
            defer { try? FileManager.default.removeItem(at: context.directory) }
            let requests = LockedCounter()
            LicenseURLProtocolStub.handler = { _ in
                _ = requests.increment()
                throw URLError(.badURL)
            }

            let allowedUnread = await context.manager.ensureValidLicense()
            let info = await context.manager.getLicenseInfo()

            XCTAssertFalse(allowedUnread, "\(initialState.status)")
            XCTAssertEqual(requests.currentValue(), 0, "\(initialState.status)")
            XCTAssertEqual(
                info.blockReason,
                LicenseBlockReason.message(
                    latch: nil,
                    clockTrusted: true,
                    machineIdentityUnavailable: true
                ),
                "\(initialState.status)"
            )
            let saved = try savedState(at: context.licensePath)
            XCTAssertEqual(saved.status, initialState.status)
            XCTAssertEqual(
                saved.validationReceipt,
                initialState.validationReceipt,
                "\(initialState.status)"
            )

            _ = successfulReads.increment()
            let allowedRead = await context.manager.ensureValidLicense()

            XCTAssertTrue(allowedRead, "\(initialState.status)")
        }
    }

    /// Service starts only on a status report. A retry that ends in offline
    /// grace must send one, the same way a retry that validates online does,
    /// or protection stays off until the user turns it on again.
    func testRetryThatEndsInOfflineGraceReportsServiceAllowed() async throws {
        let successfulReads = LockedCounter()
        let context = try makeContext(
            initialState: paidState(),
            retryPolicy: LicenseRetryPolicy(
                baseDelay: 0,
                maxAttempts: 3,
                sleep: { _ in _ = successfulReads.increment() }
            ),
            fingerprintProvider: {
                successfulReads.currentValue() > 0 ? "test-fingerprint" : nil
            }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in throw URLError(.notConnectedToInternet) }
        let allowedReports = LockedCounter()
        context.manager.onStatusChange = { _, allowed in
            if allowed { _ = allowedReports.increment() }
        }

        let initiallyAllowed = await context.manager.ensureValidLicense()
        XCTAssertFalse(initiallyAllowed)
        await context.manager.waitForPendingRetry()

        let recovered = await context.manager.isServiceAllowed()
        XCTAssertTrue(recovered)
        XCTAssertEqual(allowedReports.currentValue(), 1)
    }

    /// A denial returned to the caller sends no report, so the last report can
    /// still say allowed. Every retry that ends allowed must report again, or
    /// the second outage in a row leaves protection off.
    func testEveryRetryThatEndsInOfflineGraceReportsServiceAllowed() async throws {
        let hardwareReads = LockedCounter()
        let context = try makeContext(
            initialState: paidState(),
            retryPolicy: LicenseRetryPolicy(
                baseDelay: 0,
                maxAttempts: 3,
                sleep: { _ in _ = hardwareReads.increment() }
            ),
            fingerprintProvider: {
                hardwareReads.currentValue().isMultiple(of: 2) ? nil : "test-fingerprint"
            }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in throw URLError(.notConnectedToInternet) }
        let allowedReports = LockedCounter()
        context.manager.onStatusChange = { _, allowed in
            if allowed { _ = allowedReports.increment() }
        }

        for outage in 1...2 {
            let allowedAtOnce = await context.manager.ensureValidLicense()
            XCTAssertFalse(allowedAtOnce, "outage \(outage)")
            await context.manager.waitForPendingRetry()

            let recovered = await context.manager.isServiceAllowed()
            XCTAssertTrue(recovered, "outage \(outage)")
            XCTAssertEqual(allowedReports.currentValue(), outage)
            _ = hardwareReads.increment()
        }
    }

    /// A seat that still has to be activated is never covered by grace, with or
    /// without a hardware identity.
    func testUnreadableHardwareIdentityKeepsAPendingReactivationBlocked() async throws {
        var initialState = paidState()
        initialState.machineReactivationPending = true
        let context = try makeContext(
            initialState: initialState,
            fingerprintProvider: { nil }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in throw URLError(.badURL) }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertFalse(allowed)
    }

    /// Once the license is removed the hardware ID no longer explains anything,
    /// so the About tab must stop blaming it.
    func testDeactivationClearsTheHardwareIdentityReason() async throws {
        let context = try makeContext(
            initialState: paidState(lastValidatedAt: Date().addingTimeInterval(-(73 * 60 * 60))),
            fingerprintProvider: { nil }
        )
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            guard request.httpMethod == "DELETE" else { throw URLError(.badURL) }
            return Self.response(for: request, statusCode: 204, body: "")
        }
        let allowed = await context.manager.ensureValidLicense()
        XCTAssertFalse(allowed)

        let deactivated = await context.manager.deactivateLicense()
        let info = await context.manager.getLicenseInfo()

        XCTAssertTrue(deactivated)
        XCTAssertNil(info.blockReason)
    }

    // MARK: - Upgrade from 1.1.22

    /// The hash 1.1.22 sent for this hardware, computed independently of
    /// `MachineFingerprintPolicy` so a formula change fails these tests.
    private static let versionOneFingerprint = SHA256.hash(
        data: Data("8F2C1A9E-0B3D-5E7F-9A1B-2C3D4E5F6A7B|C02XG0FDJGH5|MacBookPro16,1".utf8)
    ).map { String(format: "%02x", $0) }.joined()

    private static let versionOneHardwareFingerprint: @Sendable () async -> String? = {
        MachineFingerprintPolicy.fingerprint(
            for: HardwareIdentityReading(
                platformUUID: "8F2C1A9E-0B3D-5E7F-9A1B-2C3D4E5F6A7B",
                serial: .present("C02XG0FDJGH5"),
                modelIdentifier: "MacBookPro16,1"
            )
        )
    }

    /// `license.json` exactly as 1.1.22 wrote it: reference-date seconds and
    /// none of the 2.x fields. The trial it names must keep working.
    func testVersionOneTrialLicenseKeepsWorkingAfterUpgrade() async throws {
        let context = try makeContext(fingerprintProvider: Self.versionOneHardwareFingerprint)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try Data(
            #"""
            {
              "expiresAt" : 915148800,
              "lastValidatedAt" : 782000000,
              "licenseId" : "trial-1",
              "status" : "trial"
            }
            """#.utf8
        ).write(to: context.licensePath)
        let creates = LockedCounter()
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialCreate(request) { _ = creates.increment() }
            return Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"\#(Self.versionOneFingerprint)","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(creates.currentValue(), 0)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .trial)
        XCTAssertEqual(saved.licenseId, "trial-1")
    }

    /// The seat 1.1.22 activated has the same fingerprint, so the upgrade must
    /// validate it without activating another machine.
    func testVersionOnePaidLicenseKeepsItsSeatAfterUpgrade() async throws {
        let context = try makeContext(fingerprintProvider: Self.versionOneHardwareFingerprint)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try Data(
            #"""
            {
              "expiresAt" : 915148800,
              "lastValidatedAt" : 782000000,
              "licenseId" : "license-1",
              "licenseKey" : "paid-key",
              "machineId" : "machine-1",
              "status" : "valid"
            }
            """#.utf8
        ).write(to: context.licensePath)
        let machineRequests = LockedCounter()
        let sentFingerprints = LockedFingerprints()
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/machines") == true { _ = machineRequests.increment() }
            if let body = LicenseTestResponseSigner.requestBody(of: request),
                let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                let scope = (json["meta"] as? [String: Any])?["scope"] as? [String: Any],
                let fingerprint = scope["fingerprint"] as? String
            {
                sentFingerprints.append(fingerprint)
            }
            return Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        }

        let allowed = await context.manager.ensureValidLicense()

        XCTAssertTrue(allowed)
        XCTAssertEqual(machineRequests.currentValue(), 0)
        XCTAssertEqual(sentFingerprints.values(), [Self.versionOneFingerprint])
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid)
        XCTAssertEqual(saved.machineId, "machine-1")
    }

    func testUnreadableHardwareIdentityReportsWhyServiceIsBlocked() async throws {
        let context = try makeContext(fingerprintProvider: { nil })
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { _ in throw URLError(.badURL) }

        let allowed = await context.manager.ensureValidLicense()
        let info = await context.manager.getLicenseInfo()

        XCTAssertFalse(allowed)
        XCTAssertEqual(
            info.blockReason,
            LicenseBlockReason.message(
                latch: nil,
                clockTrusted: true,
                licenseFileExists: false,
                machineIdentityUnavailable: true
            )
        )
    }

    /// After the user removes the unreadable file the advice to delete it is
    /// stale. Turning MacDNS on is what restores the license.
    func testRemovedUnreadableLicenseFileAsksToTurnMacDNSOn() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try Data("{ not json".utf8).write(to: context.licensePath)
        _ = await context.manager.getLicenseInfo()
        try FileManager.default.removeItem(at: context.licensePath)

        let info = await context.manager.getLicenseInfo()

        XCTAssertEqual(
            info.blockReason,
            LicenseBlockReason.message(
                latch: .stateLoadFailed,
                clockTrusted: true,
                licenseFileExists: false
            )
        )
    }

    // MARK: - Rejected activation keys

    /// Typing an expired key while a trial runs must leave the trial working:
    /// the rejected key is reported, never persisted over the current license.
    func testExpiredKeyLeavesAnActiveTrialUntouched() async throws {
        try await assertRejectedKeyLeavesLicenseUntouched(
            initialState: activeTrialState(),
            validationBody:
                #"{"meta":{"valid":false,"code":"EXPIRED"},"data":{"id":"license-2","attributes":{"expiry":"2020-01-01T00:00:00Z"}}}"#,
            expectedMessage: "License has expired"
        )
    }

    func testSuspendedKeyLeavesAValidPaidLicenseUntouched() async throws {
        try await assertRejectedKeyLeavesLicenseUntouched(
            initialState: paidState(),
            validationBody:
                #"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"license-2"}}"#,
            expectedMessage: "License has been suspended"
        )
    }

    func testExpiredKeyAfterTrialEndReportsExpiry() async throws {
        try await assertRejectedKeyLeavesLicenseUntouched(
            initialState: LicenseState(licenseId: "trial-1", status: .trialExpired),
            validationBody:
                #"{"meta":{"valid":false,"code":"EXPIRED"},"data":{"id":"license-2"}}"#,
            expectedMessage: "License has expired"
        )
    }

    /// Re-entering the installed key is a fresh verdict about that very license.
    /// Ignoring it would keep a suspended license running until the next
    /// scheduled validation.
    func testSuspendedInstalledKeyRevokesTheLicense() async throws {
        let initialState = paidState()
        let context = try makeContext(initialState: initialState)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"license-1","attributes":{"key":"paid-key"}}}"#
            )
        }
        let callback = expectation(description: "revocation callback")
        context.manager.onStatusChange = { status, allowed in
            XCTAssertEqual(status, .invalid)
            XCTAssertFalse(allowed)
            callback.fulfill()
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .error(let message) = result else {
            return XCTFail("A suspended key must report an error, got \(result)")
        }
        XCTAssertEqual(message, "License has been suspended")
        await fulfillment(of: [callback], timeout: 1)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .invalid)
        XCTAssertEqual(saved.licenseKey, initialState.licenseKey)
        let allowed = await context.manager.isServiceAllowed()
        XCTAssertFalse(allowed)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: context.licensePath.appendingPathExtension("admission-journal").path
            )
        )
    }

    func testExpiredInstalledKeyExpiresTheLicense() async throws {
        let context = try makeContext(initialState: paidState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            Self.response(
                for: request,
                statusCode: 200,
                body:
                    #"{"meta":{"valid":false,"code":"EXPIRED"},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2020-01-01T00:00:00Z"}}}"#
            )
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .error(let message) = result else {
            return XCTFail("An expired key must report an error, got \(result)")
        }
        XCTAssertEqual(message, "License has expired")
        XCTAssertEqual(try savedState(at: context.licensePath).status, .expired)
    }

    private func assertRejectedKeyLeavesLicenseUntouched(
        initialState: LicenseState,
        validationBody: String,
        expectedMessage: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let context = try makeContext(initialState: initialState)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        await context.manager.initialize()
        LicenseURLProtocolStub.handler = { request in
            XCTAssertTrue(
                request.url?.path.hasSuffix("/licenses/actions/validate-key") == true,
                file: file,
                line: line
            )
            return Self.response(for: request, statusCode: 200, body: validationBody)
        }

        let result = await context.manager.activateLicense(key: "rejected-key")

        guard case .error(let message) = result else {
            return XCTFail("Rejected key must report an error, got \(result)", file: file, line: line)
        }
        XCTAssertEqual(message, expectedMessage, file: file, line: line)
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.licenseKey, initialState.licenseKey, file: file, line: line)
        XCTAssertEqual(saved.licenseId, initialState.licenseId, file: file, line: line)
        XCTAssertEqual(saved.machineId, initialState.machineId, file: file, line: line)
        XCTAssertEqual(saved.status, initialState.status, file: file, line: line)
        XCTAssertEqual(saved.lastValidatedAt, initialState.lastValidatedAt, file: file, line: line)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: context.licensePath.appendingPathExtension("admission-journal").path
            ),
            file: file,
            line: line
        )
    }

    // MARK: - Local clock skew

    /// With the Mac clock 10 minutes off and nothing verified yet, a signed
    /// answer must not be rejected as stale, or no trial can ever be created.
    func testTrialRegistersWhenTheLocalClockIsTenMinutesOff() async throws {
        for skew in [600.0, -600.0] {
            let context = try makeContext(wallClock: { Date().addingTimeInterval(skew) })
            defer { try? FileManager.default.removeItem(at: context.directory) }
            LicenseURLProtocolStub.handler = { request in
                Self.trialCreationResponse(for: request)
            }

            let allowed = await context.manager.ensureValidLicense()

            XCTAssertTrue(allowed, "skew \(skew)")
            XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
        }
    }

    /// The machine create carries no nonce. It must be judged against the server
    /// time the nonce-bound key validation just proved, not the wrong wall clock.
    func testPaidActivationSucceedsWhenTheLocalClockIsTenMinutesOff() async throws {
        let context = try makeContext(wallClock: { Date().addingTimeInterval(-600) })
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/licenses/actions/validate-key") == true {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            }
            XCTAssertTrue(request.url?.path.hasSuffix("/machines") == true)
            return Self.response(
                for: request,
                statusCode: 201,
                body: #"{"data":{"id":"machine-1"}}"#
            )
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .success = result else {
            return XCTFail("Activation must succeed despite clock skew, got \(result)")
        }
        let saved = try savedState(at: context.licensePath)
        XCTAssertEqual(saved.status, .valid)
        XCTAssertEqual(saved.machineId, "machine-1")
    }

    func testTrialCreatedWithServicesStoppedSchedulesNoValidation() async throws {
        let context = try makeContext(initialState: LicenseState())
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { Self.trialCreationResponse(for: $0) }

        let info = await context.manager.validateLicense()

        XCTAssertEqual(info.status, .trial)
        XCTAssertTrue(info.isServiceAllowed)
        XCTAssertEqual(try savedState(at: context.licensePath).status, .trial)
        let scheduled = await context.manager.isValidationScheduled()
        XCTAssertFalse(scheduled)
    }

    func testServicesRunningArmsAndStoppingCancelsValidation() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }

        await context.manager.setServicesRunning(true)?.value
        let armed = await context.manager.isValidationScheduled()
        XCTAssertTrue(armed)

        context.manager.setServicesRunning(false)
        let cancelled = await context.manager.isValidationScheduled()
        XCTAssertFalse(cancelled)
    }

    func testPaidActivationWithServicesStoppedSchedulesNoValidation() async throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        LicenseURLProtocolStub.handler = { request in
            if Self.isTrialLookup(request) {
                return Self.response(
                    for: request,
                    statusCode: 200,
                    body:
                        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
                )
            }
            return Self.response(for: request, statusCode: 201, body: #"{"data":{"id":"machine-1"}}"#)
        }

        let result = await context.manager.activateLicense(key: "paid-key")

        guard case .success = result else {
            return XCTFail("Activation must succeed, got \(result)")
        }
        XCTAssertEqual(try savedState(at: context.licensePath).status, .valid)
        let scheduled = await context.manager.isValidationScheduled()
        XCTAssertFalse(scheduled)
    }

    /// Production order: the agent validates before it starts services, so the
    /// grace deadline is requested while nothing may arm. Starting services
    /// must arm for that deadline, not for the far-off license expiry.
    func testServicesStartedAfterGraceValidationArmTheTimerForTheGraceDeadline() async throws {
        let graceEndsSoon = Date().addingTimeInterval(-LicenseFailClosedPolicy.gracePeriod + 8)
        let context = try makeContext(initialState: paidState(lastValidatedAt: graceEndsSoon))
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let requestCount = LockedCounter()
        LicenseURLProtocolStub.handler = { _ in
            _ = requestCount.increment()
            throw URLError(.notConnectedToInternet)
        }

        let allowed = await context.manager.ensureValidLicense()
        XCTAssertTrue(allowed, "Validation inside grace must admit service")
        let requestsBeforeTimer = requestCount.currentValue()
        await context.manager.setServicesRunning(true)?.value
        defer { context.manager.setServicesRunning(false) }

        let deadline = Date().addingTimeInterval(20)
        while requestCount.currentValue() == requestsBeforeTimer, Date() < deadline {
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTAssertGreaterThan(
            requestCount.currentValue(),
            requestsBeforeTimer,
            "Grace expiry must trigger a validation while services run"
        )
    }

    func testStopRightAfterStartLeavesNoValidationScheduled() async throws {
        let context = try makeContext(initialState: activeTrialState())
        defer { try? FileManager.default.removeItem(at: context.directory) }

        let arming = context.manager.setServicesRunning(true)
        context.manager.setServicesRunning(false)
        await arming?.value

        let scheduled = await context.manager.isValidationScheduled()
        XCTAssertFalse(scheduled)
    }

    private func makeContext(
        initialState: LicenseState? = nil,
        validationWaitTimeout: TimeInterval = 30,
        retryPolicy: LicenseRetryPolicy = LicenseMachineReactivationTests.disabledRetryPolicy,
        wallClock: @escaping @Sendable () -> Date = { Date() },
        fingerprintProvider: @escaping @Sendable () async -> String? = {
            "test-fingerprint"
        },
        trialToken: String? = LicenseMachineReactivationTests.testTrialToken
    ) throws -> TestContext {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let licensePath = directory.appendingPathComponent("license.json")
        if let initialState {
            let data = try JSONCoding.encoder.encode(initialState)
            try data.write(to: licensePath, options: .atomic)
        }

        return TestContext(
            directory: directory,
            licensePath: licensePath,
            manager: makeManager(
                licensePath: licensePath,
                validationWaitTimeout: validationWaitTimeout,
                retryPolicy: retryPolicy,
                wallClock: wallClock,
                fingerprintProvider: fingerprintProvider,
                trialToken: trialToken
            )
        )
    }

    private func makeManager(
        licensePath: URL,
        validationWaitTimeout: TimeInterval = 30,
        retryPolicy: LicenseRetryPolicy = LicenseMachineReactivationTests.disabledRetryPolicy,
        wallClock: @escaping @Sendable () -> Date = { Date() },
        fingerprintProvider: @escaping @Sendable () async -> String? = {
            "test-fingerprint"
        },
        trialToken: String? = LicenseMachineReactivationTests.testTrialToken
    ) -> LicenseManager {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LicenseURLProtocolStub.self]
        return LicenseManager(
            session: URLSession(configuration: configuration),
            licensePath: licensePath,
            validationWaitTimeout: validationWaitTimeout,
            fingerprintProvider: fingerprintProvider,
            verifier: Self.signer.makeVerifier(),
            retryPolicy: retryPolicy,
            wallClock: wallClock,
            trialToken: trialToken
        )
    }

    private static let testTrialToken = "test-trial-token"

    private func paidState(
        lastValidatedAt: Date = Date()
    ) -> LicenseState {
        LicenseState(
            licenseKey: "paid-key",
            licenseId: "license-1",
            machineId: "machine-old",
            status: .valid,
            expiresAt: Date(timeIntervalSince1970: 1_893_456_000),
            lastValidatedAt: lastValidatedAt,
            validationReceipt: Self.signer.receipt(
                body: Self.validPaidAnswerBody,
                date: lastValidatedAt
            )
        )
    }

    private func activeTrialState(
        lastValidatedAt: Date = Date()
    ) -> LicenseState {
        LicenseState(
            licenseId: "trial-1",
            status: .trial,
            expiresAt: Date(timeIntervalSince1970: 1_893_456_000),
            lastValidatedAt: lastValidatedAt,
            validationReceipt: Self.signer.receipt(
                body: Self.liveTrialLookupBody,
                date: lastValidatedAt
            )
        )
    }

    private func savedState(at path: URL) throws -> LicenseState {
        try JSONCoding.decoder.decode(
            LicenseState.self,
            from: Data(contentsOf: path)
        )
    }

    /// A paid answer as Keygen signs it for this machine, scope echoed.
    private static let validPaidAnswerBody =
        #"{"meta":{"valid":true,"code":"VALID","scope":{"fingerprint":"test-fingerprint","product":"b2ace9b9-0a7e-43ca-8866-be62d6ec80e0"}},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2030-01-01T00:00:00Z"}}}"#
    /// The same answer for a Mac that holds another seat of the license.
    private static let donorPaidAnswerBody =
        #"{"meta":{"valid":true,"code":"VALID","scope":{"fingerprint":"donor-fingerprint","product":"b2ace9b9-0a7e-43ca-8866-be62d6ec80e0"}},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2030-01-01T00:00:00Z"}}}"#
    /// What the stub answers to a paid validation. The signer echoes the scope.
    private static let validPaidValidationBody =
        #"{"meta":{"valid":true,"code":"VALID"},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2030-01-01T00:00:00Z"}}}"#
    private static let renewedPaidValidationBody =
        #"{"meta":{"valid":true,"code":"VALID"},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2031-01-01T00:00:00Z"}}}"#
    private static let liveTrialLookupBody =
        #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"test-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
    private static let endedTrialLookupBody =
        #"{"meta":{"valid":false,"code":"EXPIRED"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"test-fingerprint","expiry":"2020-01-01T00:00:00Z"}}}"#
    /// A live trial of another machine, as a proxy that asked about a donor
    /// fingerprint would relay it.
    private static let donorTrialLookupBody =
        #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"donor-trial","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"donor-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
    private static let unknownTrialLookupBody =
        #"{"meta":{"valid":false,"code":"NOT_FOUND"},"data":null}"#
    private static let keyTakenBody =
        #"{"errors":[{"title":"Unprocessable resource","detail":"has already been taken","code":"KEY_TAKEN","source":{"pointer":"/data/attributes/key"}}]}"#

    private static func isTrialLookup(_ request: URLRequest) -> Bool {
        request.url?.path.hasSuffix("/licenses/actions/validate-key") == true
    }

    private static func isTrialCreate(_ request: URLRequest) -> Bool {
        request.httpMethod == "POST" && request.url?.path.hasSuffix("/licenses") == true
    }

    /// A machine Keygen has never seen: the lookup finds nothing and the create
    /// succeeds.
    private static func trialCreationResponse(
        for request: URLRequest
    ) -> (HTTPURLResponse, Data) {
        if isTrialLookup(request) {
            return response(for: request, statusCode: 200, body: unknownTrialLookupBody)
        }
        return response(
            for: request,
            statusCode: 201,
            body:
                #"{"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"f84203af-417a-4337-9153-2124fdcc2ca8"}}},"attributes":{"key":"test-fingerprint","expiry":"2030-01-01T00:00:00Z"}}}"#
        )
    }

    private static let suspendedPaidValidationBody =
        #"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"license-1","attributes":{"key":"paid-key"}}}"#
    private static let expiredPaidValidationBody =
        #"{"meta":{"valid":false,"code":"EXPIRED"},"data":{"id":"license-1","attributes":{"key":"paid-key","expiry":"2020-01-01T00:00:00Z"}}}"#

    private static let noMachineValidationBody =
        #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#

    private static let machineLimitBody =
        #"{"errors":[{"title":"Unprocessable resource","detail":"machine count has exceeded maximum allowed for license (2)","code":"MACHINE_LIMIT_EXCEEDED","source":{"pointer":"/data"}}]}"#

    private static let fingerprintTakenBody =
        #"{"errors":[{"title":"Unprocessable resource","detail":"has already been taken","code":"FINGERPRINT_TAKEN","source":{"pointer":"/data/attributes/fingerprint"}}]}"#

    private static let unknownMachineRejectionBody =
        #"{"errors":[{"title":"Unprocessable resource","detail":"is invalid","code":"NAME_INVALID","source":{"pointer":"/data/attributes/name"}}]}"#

    /// Signed exactly like a genuine Keygen response, so these tests exercise the
    /// verified path instead of silently depending on unverified bodies.
    private static func response(
        for request: URLRequest,
        statusCode: Int,
        body: String
    ) -> (HTTPURLResponse, Data) {
        signer.response(for: request, statusCode: statusCode, body: body)
    }
}
