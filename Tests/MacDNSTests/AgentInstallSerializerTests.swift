// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class AgentInstallSerializerTests: XCTestCase {

    private struct InstallFailure: Error, Equatable {}

    /// An install that stays in flight until the test finishes it.
    @MainActor
    private final class HeldInstall {
        private(set) var executions: [String] = []
        private var completions: [CheckedContinuation<Void, Error>] = []

        var isInFlight: Bool { !completions.isEmpty }

        func install(_ caller: String) -> @MainActor () async throws -> Void {
            {
                self.executions.append(caller)
                try await withCheckedThrowingContinuation {
                    self.completions.append($0)
                }
            }
        }

        func finish(with result: Result<Void, Error>) {
            completions.forEach { $0.resume(with: result) }
            completions.removeAll()
        }
    }

    func testConcurrentCallersRunOneInstallAndBothSucceed() async {
        let results = await raceTwoCallers(finishingWith: .success(()))

        XCTAssertEqual(results.executions, ["first"])
        XCTAssertNil(results.first)
        XCTAssertNil(results.second)
    }

    func testConcurrentCallersSeeTheSameInstallError() async {
        let results = await raceTwoCallers(
            finishingWith: .failure(InstallFailure())
        )

        XCTAssertEqual(results.executions, ["first"])
        XCTAssertEqual(results.first as? InstallFailure, InstallFailure())
        XCTAssertEqual(results.second as? InstallFailure, InstallFailure())
    }

    func testRunningTaskIsExposedOnlyWhileAnInstallRuns() async throws {
        let serializer = AgentInstallSerializer()
        let held = HeldInstall()
        XCTAssertNil(serializer.running)

        let caller = Task { @MainActor in
            try await serializer.run(held.install("only"))
        }
        while !held.isInFlight { await Task.yield() }
        XCTAssertNotNil(serializer.running)

        held.finish(with: .success(()))
        try await caller.value
        XCTAssertNil(serializer.running)
    }

    /// The Agent replacement waits for the running install and then runs its
    /// own. Joining the finished one instead would skip its unregistration.
    func testAWaiterOfTheRunningInstallRunsItsOwnInstall() async throws {
        let serializer = AgentInstallSerializer()
        let held = HeldInstall()
        var waiterExecutions = 0

        let first = Task { @MainActor in
            try await serializer.run(held.install("first"))
        }
        while !held.isInFlight { await Task.yield() }
        let running = try XCTUnwrap(serializer.running)
        var waiterIsWaiting = false
        let waiter = Task { @MainActor in
            waiterIsWaiting = true
            _ = try? await running.value
            try await serializer.run { waiterExecutions += 1 }
        }
        while !waiterIsWaiting { await Task.yield() }

        held.finish(with: .success(()))
        try await waiter.value
        try await first.value

        XCTAssertEqual(waiterExecutions, 1)
    }

    func testAnInstallAfterAFailedOneRunsAgain() async throws {
        let serializer = AgentInstallSerializer()
        var executions = 0

        do {
            try await serializer.run {
                executions += 1
                throw InstallFailure()
            }
            XCTFail("The failed install must throw")
        } catch {
            XCTAssertEqual(error as? InstallFailure, InstallFailure())
        }
        XCTAssertNil(serializer.running)

        try await serializer.run { executions += 1 }
        XCTAssertEqual(executions, 2)
    }

    private func raceTwoCallers(
        finishingWith result: Result<Void, Error>
    ) async -> (executions: [String], first: Error?, second: Error?) {
        let serializer = AgentInstallSerializer()
        let held = HeldInstall()
        var callersStarted = 0

        func caller(_ name: String) -> Task<Void, Error> {
            Task { @MainActor in
                callersStarted += 1
                try await serializer.run(held.install(name))
            }
        }
        let first = caller("first")
        let second = caller("second")
        while callersStarted < 2 || !held.isInFlight { await Task.yield() }

        held.finish(with: result)
        let firstError = await first.result.failure
        let secondError = await second.result.failure
        return (held.executions, firstError, secondError)
    }
}

extension Result {
    fileprivate var failure: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
