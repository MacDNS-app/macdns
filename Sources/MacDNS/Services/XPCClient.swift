// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

public enum XPCError: Error, LocalizedError {
    /// The connection failed or the remote proxy is unavailable.
    case agentNotResponding

    case timeout

    /// The agent crashed or restarted mid-call.
    case connectionInterrupted

    case decodingFailed(String)

    case agentError(String)

    /// The agent answered that it could not read `state.json`.
    case agentStateUnreadable

    public var errorDescription: String? {
        switch self {
        case .agentNotResponding:
            return "Agent is not responding"
        case .timeout:
            return "Operation timed out"
        case .connectionInterrupted:
            return "Connection to agent was interrupted"
        case .decodingFailed(let details):
            return "Failed to decode response: \(details)"
        case .agentError(let message):
            return message
        case .agentStateUnreadable:
            return "The agent could not read the configuration file"
        }
    }
}

extension FullConfigReadResponse {
    /// What `getFullConfigAsync` returns for this answer. Only an I/O failure
    /// can clear on a later read.
    var loadResult: Result<[String: Any], XPCError> {
        switch status {
        case .loaded:
            guard let config, FullConfigPayloadPolicy.isValidPayload(config) else {
                return .failure(.decodingFailed("Non-JSON configuration payload"))
            }
            return .success(config)
        case .ioFailure:
            return .failure(.agentStateUnreadable)
        case .invalid:
            return .failure(.agentError("The configuration file is invalid"))
        case .incompatibleSchema:
            return .failure(
                .agentError("The configuration file was written by a newer MacDNS")
            )
        }
    }
}

class XPCClient {
    static let shared = XPCClient()

    /// The App sends the license key over this channel, so the Agent must prove
    /// it is the MacDNS agent before the connection is resumed. The Agent's
    /// identity is already pinned once for the proxy-control plane. Reusing that
    /// constant keeps a single Team ID source, which the build's
    /// `check_source_signing_inputs` ties to the identity it actually signs with.
    static let agentCodeRequirement = proxyControlAgentRequirement

    private let logger = AppLogger.shared.xpc

    private var connection: NSXPCConnection?
    private let connectionQueue = DispatchQueue(label: "app.macdns.xpc.connection")
    private let makeConnection: () -> NSXPCConnection

    init(
        makeConnection: @escaping () -> NSXPCConnection = {
            NSXPCConnection(machServiceName: "app.macdns.agent", options: [])
        }
    ) {
        self.makeConnection = makeConnection
    }

    /// Invalidation fires on every failed attempt, so the reason is logged once
    /// per App session: enough to diagnose a rejected Agent, not enough to flood.
    private var didLogConnectionInvalidation = false

    private let defaultTimeout: TimeInterval = 5.0

    /// Starting the resolver, validating and activating each wait for one
    /// license operation in the Agent. The margin covers XPC and, on resolver
    /// start, starting the services.
    static let licenseReplyTimeout = LicenseRequestBudget.operation + 15

    /// A full-config write applies runtime state in the Agent, so it needs a
    /// wider budget than a read, but never an unbounded one.
    private let fullConfigSaveTimeout: TimeInterval = 30.0

    /// Clearing closes, deletes and recreates the history database.
    private let queryHistoryClearTimeout: TimeInterval = 15.0

    /// Thread-safe wrapper ensuring a CheckedContinuation is resumed at most once.
    /// Prevents data races when XPC callbacks and error handlers could fire concurrently.
    private final class SafeContinuation<T>: @unchecked Sendable {
        private var continuation: CheckedContinuation<T, Never>?
        private let lock = NSLock()

        init(_ continuation: CheckedContinuation<T, Never>) {
            self.continuation = continuation
        }

        func resume(returning value: T) {
            let cont: CheckedContinuation<T, Never>?
            lock.lock()
            cont = continuation
            continuation = nil
            lock.unlock()
            cont?.resume(returning: value)
        }
    }

    // MARK: - Timeout Helper

    /// Wraps an async XPC operation with a hard timeout.
    /// Uses DispatchWorkItem + SafeContinuation instead of TaskGroup to guarantee
    /// the caller is unblocked even if the operation's continuation is never resumed
    /// (e.g. agent hangs without crashing).
    private func withTimeout<T>(
        seconds: TimeInterval? = nil,
        operation: @escaping () async -> T?
    ) async -> T? {
        let timeout = seconds ?? defaultTimeout

        return await withCheckedContinuation { continuation in
            let safe = SafeContinuation(continuation)

            let timeoutWork = DispatchWorkItem {
                safe.resume(returning: nil)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

            Task {
                let result = await operation()
                timeoutWork.cancel()
                safe.resume(returning: result)
            }
        }
    }

    // MARK: - Result-Based XPC Operations

    /// `withTimeout` returning `Result`, with the same guarantee that the caller is unblocked.
    private func withResultTimeout<T>(
        seconds: TimeInterval? = nil,
        operation: @escaping () async -> Result<T, XPCError>
    ) async -> Result<T, XPCError> {
        let timeout = seconds ?? defaultTimeout

        return await withCheckedContinuation { continuation in
            let safe = SafeContinuation(continuation)

            let timeoutWork = DispatchWorkItem {
                safe.resume(returning: .failure(.timeout))
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

            Task {
                let result = await operation()
                timeoutWork.cancel()
                safe.resume(returning: result)
            }
        }
    }

    // MARK: - Result-Based Async Methods

    func startResolverAsync() async -> Result<Bool, XPCError> {
        await withResultTimeout(seconds: Self.licenseReplyTimeout) { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.startResolver { success in
                    if success {
                        self.logger.info("Agent started successfully")
                        safe.resume(returning: .success(true))
                    } else {
                        self.logger.error("Failed to start Agent")
                        safe.resume(returning: .failure(.agentError("Failed to start services")))
                    }
                }
            }
        }
    }

    /// - Parameter force: Skips cache persistence for a fast shutdown.
    func stopResolverAsync(force: Bool = false) async -> Result<Bool, XPCError> {
        await withCheckedContinuation { continuation in
            BoundedCallback.run(
                seconds: defaultTimeout, timeoutValue: Result<Bool, XPCError>.failure(.timeout),
                completion: {
                    continuation.resume(returning: $0)
                }
            ) { finish in
                guard let proxy = getProxy(handler: { _ in finish(.failure(.agentNotResponding)) }) else {
                    finish(.failure(.agentNotResponding))
                    return
                }
                proxy.stopResolverForce(force: force) { finish(.success($0)) }
            }
        }
    }

    /// - Parameter timeout: Overrides the default budget when the caller has a
    ///   deadline of its own, such as a bounded agent-readiness wait.
    func getFullConfigAsync(
        timeout: TimeInterval? = nil
    ) async -> Result<[String: Any], XPCError> {
        await withResultTimeout(seconds: timeout) { [self] in
            guard let response = await self.readFullConfigResponse() else {
                return await self.getFullConfigWithoutReason()
            }
            if response.status != .loaded {
                self.logger.error(
                    "Agent could not serve the configuration: \(response.status.rawValue, privacy: .public)"
                )
            }
            return response.loadResult
        }
    }

    /// `nil` when the call produced no usable answer. An Agent built before
    /// `readFullConfig` drops the connection on the unknown selector, and the
    /// next call reconnects.
    private func readFullConfigResponse() async -> FullConfigReadResponse? {
        await withCheckedContinuation { continuation in
            let safe = SafeContinuation(continuation)

            guard
                let proxy = self.getProxy(handler: { _ in
                    safe.resume(returning: nil)
                })
            else {
                safe.resume(returning: nil)
                return
            }

            proxy.readFullConfig { data in
                safe.resume(returning: FullConfigReadResponse.decoded(from: data))
            }
        }
    }

    /// The read every Agent build answers. It cannot say why no configuration
    /// came back.
    private func getFullConfigWithoutReason() async -> Result<[String: Any], XPCError> {
        await withCheckedContinuation { continuation in
            let safe = SafeContinuation(continuation)

            guard
                let proxy = self.getProxy(handler: { _ in
                    safe.resume(returning: .failure(.agentNotResponding))
                })
            else {
                safe.resume(returning: .failure(.agentNotResponding))
                return
            }

            proxy.getFullConfig { config in
                guard let config = config else {
                    safe.resume(returning: .failure(.agentError("No configuration returned")))
                    return
                }
                guard FullConfigPayloadPolicy.isValidPayload(config) else {
                    self.logger.error("Agent returned a non-JSON configuration payload")
                    safe.resume(
                        returning: .failure(
                            .decodingFailed("Non-JSON configuration payload")
                        )
                    )
                    return
                }
                safe.resume(returning: .success(config))
            }
        }
    }

    /// Full-config writes normally complete from the XPC reply or error handler.
    /// The watchdog reports `.timeout` without cancelling the Agent-side
    /// transaction, so `FullConfigSaveCoordinator` treats it as a stalled save:
    /// it keeps the snapshot and starts no second transaction until an
    /// authoritative reload confirms the revision.
    func saveFullConfigAsync(
        config: [String: Any]
    ) async -> Result<FullConfigSaveResponse, XPCError> {
        guard FullConfigPayloadPolicy.isValidPayload(config) else {
            logger.error("Refusing to send a non-JSON configuration payload to the agent")
            return .success(
                FullConfigSaveResponse(
                    status: .rejected,
                    rejectionReason: .invalidConfiguration
                )
            )
        }
        return await withResultTimeout(seconds: fullConfigSaveTimeout) { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.saveFullConfig(config: config) { data in
                    guard let response = FullConfigSaveResponse.decoded(from: data)
                    else {
                        self.logger.warning("Agent returned an undecodable save response")
                        safe.resume(
                            returning: .failure(
                                .decodingFailed("FullConfigSaveResponse")
                            )
                        )
                        return
                    }
                    if !response.isPersisted {
                        self.logger.warning(
                            "Configuration save not persisted: \(response.status.rawValue, privacy: .public)"
                        )
                    }
                    safe.resume(returning: .success(response))
                }
            }
        }
    }

    func getLicenseInfoAsync() async -> Result<LicenseInfo, XPCError> {
        await withResultTimeout { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.getLicenseInfo { data in
                    guard let data = data else {
                        safe.resume(returning: .failure(.agentError("No license info returned")))
                        return
                    }
                    do {
                        let info = try JSONCoding.decoder.decode(LicenseInfo.self, from: data)
                        safe.resume(returning: .success(info))
                    } catch {
                        safe.resume(returning: .failure(.decodingFailed(error.localizedDescription)))
                    }
                }
            }
        }
    }

    func activateLicenseAsync(licenseKey: String) async -> Result<LicenseActivationResult, XPCError> {
        await withResultTimeout(seconds: Self.licenseReplyTimeout) { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.activateLicense(licenseKey: licenseKey) { data in
                    guard let data = data else {
                        safe.resume(returning: .failure(.agentError("No activation result returned")))
                        return
                    }
                    do {
                        let result = try JSONCoding.decoder.decode(LicenseActivationResult.self, from: data)
                        safe.resume(returning: .success(result))
                    } catch {
                        safe.resume(returning: .failure(.decodingFailed(error.localizedDescription)))
                    }
                }
            }
        }
    }

    /// Asks the agent to validate the license, which registers the trial when none exists.
    func validateLicenseAsync() async -> Result<LicenseInfo, XPCError> {
        await withResultTimeout(seconds: Self.licenseReplyTimeout) { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.validateLicense { data in
                    guard let data = data else {
                        safe.resume(returning: .failure(.agentError("No license info returned")))
                        return
                    }
                    do {
                        let info = try JSONCoding.decoder.decode(LicenseInfo.self, from: data)
                        safe.resume(returning: .success(info))
                    } catch {
                        safe.resume(returning: .failure(.decodingFailed(error.localizedDescription)))
                    }
                }
            }
        }
    }

    func isServicesRunningAsync() async -> Result<Bool, XPCError> {
        await withResultTimeout { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.isServicesRunning { running in
                    safe.resume(returning: .success(running))
                }
            }
        }
    }

    func getRuntimeStateAsync() async -> Result<AgentRuntimeState, XPCError> {
        await withResultTimeout { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)
                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.getRuntimeState { data in
                    guard let data else {
                        safe.resume(
                            returning: .failure(
                                .decodingFailed("Missing runtime state")
                            )
                        )
                        return
                    }
                    do {
                        let snapshot = try JSONCoding.decoder.decode(
                            AgentRuntimeStateSnapshot.self,
                            from: data
                        )
                        safe.resume(
                            returning: .success(
                                AgentRuntimeState(snapshot: snapshot)
                            )
                        )
                    } catch {
                        safe.resume(
                            returning: .failure(
                                .decodingFailed(error.localizedDescription)
                            )
                        )
                    }
                }
            }
        }
    }

    func getConnection() -> NSXPCConnection {
        connectionQueue.sync {
            if let connection = connection {
                return connection
            }

            let newConnection = makeConnection()
            let remoteInterface = NSXPCInterface(with: MacDNSXPCProtocol.self)
            FullConfigPayloadPolicy.restrictPayloadClasses(on: remoteInterface)
            newConnection.remoteObjectInterface = remoteInterface

            // An interrupted connection stays valid and reaches the relaunched
            // Agent on its next message, so it is kept. A used connection that
            // is dropped without `invalidate()` is never released.
            newConnection.interruptionHandler = { [weak self] in
                self?.logger.warning("XPC connection interrupted")
            }

            // Handlers run on an XPC thread. Hopping to connectionQueue
            // asynchronously avoids a deadlock. A connection that was already
            // replaced must not drop its successor.
            newConnection.invalidationHandler = { [weak self, weak newConnection] in
                guard let self = self else { return }
                self.connectionQueue.async {
                    guard let newConnection, self.connection === newConnection else { return }
                    self.logFirstConnectionInvalidation()
                    self.connection = nil
                }
            }

            newConnection.setCodeSigningRequirement(Self.agentCodeRequirement)
            newConnection.resume()
            self.connection = newConnection
            return newConnection
        }
    }

    /// Must run on `connectionQueue`.
    private func logFirstConnectionInvalidation() {
        guard !didLogConnectionInvalidation else { return }
        didLogConnectionInvalidation = true
        logger.warning(
            "XPC connection invalidated: agent absent or failing \(Self.agentCodeRequirement, privacy: .public)"
        )
    }

    /// Call after an agent reinstall.
    func resetConnection() {
        connectionQueue.async { [weak self] in
            guard let self, let connection = self.connection else { return }
            // Cleared first, so this deliberate teardown is not reported as an
            // unusable Agent channel.
            self.connection = nil
            connection.invalidate()
        }
    }

    private func getProxy(handler: @escaping (Error) -> Void) -> MacDNSXPCProtocol? {
        let connection = getConnection()
        return connection.remoteObjectProxyWithErrorHandler { error in
            // The error handler runs on an XPC background thread, and callers
            // update UI state.
            DispatchQueue.main.async {
                handler(error)
            }
        } as? MacDNSXPCProtocol
    }

    func startResolver(completion: @escaping (Bool) -> Void) {
        Task {
            let result = await startResolverAsync()
            let success: Bool

            switch result {
            case .success(let didStart):
                success = didStart
            case .failure(let error):
                self.logger.error("Failed to start Agent: \(error.localizedDescription, privacy: .public)")
                success = false
            }

            DispatchQueue.main.async { completion(success) }
        }
    }

    func stopResolver(force: Bool = false, completion: @escaping (Bool) -> Void) {
        Task {
            let result = await stopResolverAsync(force: force)
            let success = (try? result.get()) ?? false
            DispatchQueue.main.async { completion(success) }
        }
    }

    func isServicesRunning(completion: @escaping (Bool) -> Void) {
        getProxy { _ in completion(false) }?.isServicesRunning { running in
            DispatchQueue.main.async { completion(running) }
        }
    }

    // MARK: - Binary Hash Management

    /// SHA256 of the running agent's executable, or nil when the agent does not
    /// answer in time.
    func getAgentBinaryHash() async -> String? {
        await withTimeout {
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard let proxy = self.getProxy(handler: { _ in safe.resume(returning: nil) }) else {
                    safe.resume(returning: nil)
                    return
                }
                proxy.getAgentBinaryHash { hash in
                    safe.resume(returning: hash)
                }
            }
        }
    }

    // MARK: - Full Configuration Management

    /// Bounded by `getFullConfigAsync` so a hung Agent cannot strand the caller.
    func getFullConfig(completion: @escaping ([String: Any]?) -> Void) {
        Task { [self] in
            let config = try? await getFullConfigAsync().get()
            DispatchQueue.main.async { completion(config) }
        }
    }

    // MARK: - Captive Portal Support

    func getCaptivePortalStatus(completion: @escaping (String?, String?) -> Void) {
        getProxy { _ in completion(nil, nil) }?.getCaptivePortalStatus { combined in
            DispatchQueue.main.async {
                let parts = combined.components(separatedBy: "|")
                if parts.count == 2 {
                    completion(parts[0], parts[1])
                } else {
                    completion(nil, nil)
                }
            }
        }
    }

    func getResolverMode(completion: @escaping (String?) -> Void) {
        getProxy { _ in completion(nil) }?.getResolverMode { mode in
            DispatchQueue.main.async { completion(mode) }
        }
    }

    func recheckCaptivePortal(completion: @escaping (Bool) -> Void) {
        getProxy { _ in completion(false) }?.recheckCaptivePortal { success in
            DispatchQueue.main.async { completion(success) }
        }
    }

    /// Grants a full captive-portal bypass on the agent for the currently
    /// attached network. An agent that does not implement the method makes NSXPC
    /// fail the message, which lands in the error handler as a refusal.
    func approveCaptivePortalBypass(completion: @escaping (Bool) -> Void) {
        getProxy { _ in completion(false) }?.approveCaptivePortalBypass { approved in
            DispatchQueue.main.async { completion(approved) }
        }
    }

    // MARK: - Blocklist Management

    func getBlocklistSettings(completion: @escaping (BlocklistSettings?) -> Void) {
        BoundedCallback.run(
            seconds: defaultTimeout, timeoutValue: nil as BlocklistSettings?,
            completion: { value in
                DispatchQueue.main.async { completion(value) }
            },
            operation: { finish in
                guard let proxy = getProxy(handler: { _ in finish(nil) }) else {
                    finish(nil)
                    return
                }
                proxy.getBlocklistSettings { data in
                    guard let data,
                        let settings = try? JSONCoding.decoder.decode(BlocklistSettings.self, from: data)
                    else {
                        self.logger.error("Failed to decode blocklist settings from agent")
                        finish(nil)
                        return
                    }
                    finish(settings)
                }
            }
        )
    }

    func saveBlocklistSettings(
        settings: BlocklistSettings,
        onLateReply: @escaping (BlocklistSaveResult) -> Void = { _ in },
        completion: @escaping (BlocklistSaveResult) -> Void
    ) {
        guard let data = try? JSONCoding.encoder.encode(settings) else {
            logger.error("Failed to encode blocklist settings for agent")
            completion(.encodingFailed)
            return
        }
        BoundedCallback.run(
            seconds: fullConfigSaveTimeout, timeoutValue: BlocklistSaveResult.timedOut,
            completion: { value in
                DispatchQueue.main.async { completion(value) }
            },
            onLateReply: { value in
                DispatchQueue.main.async { onLateReply(value) }
            },
            operation: { finish in
                guard let proxy = getProxy(handler: { _ in finish(.agentUnavailable) }) else {
                    finish(.agentUnavailable)
                    return
                }
                proxy.saveBlocklistSettings(settingsData: data) { finish($0 ? .saved : .rejectedByAgent) }
            }
        )
    }

    func forceBlocklistUpdate(completion: @escaping (Bool) -> Void) {
        BoundedCallback.run(
            seconds: fullConfigSaveTimeout, timeoutValue: false,
            completion: { value in
                DispatchQueue.main.async { completion(value) }
            },
            operation: { finish in
                guard let proxy = getProxy(handler: { _ in finish(false) }) else {
                    finish(false)
                    return
                }
                proxy.forceBlocklistUpdate { finish($0) }
            }
        )
    }

    // MARK: - Cache Management

    func flushCache(completion: @escaping (Bool) -> Void) {
        getProxy { _ in completion(false) }?.flushCache { success in
            DispatchQueue.main.async { completion(success) }
        }
    }

    // MARK: - Lookup History

    /// Sends one `dns_history_query` request through the agent. A transport
    /// failure, a timeout or an undecodable answer is an `XPCError`. The
    /// resolver's own `disabled`, `unavailable` and `error` answers are a
    /// successful `QueryHistoryResponse`.
    func queryHistory<Payload: Decodable & Equatable>(
        _ request: QueryHistoryRequest,
        as _: Payload.Type
    ) async -> Result<QueryHistoryResponse<Payload>, XPCError> {
        guard let body = try? request.encoded() else {
            return .failure(.agentError("Cannot encode the lookup history request"))
        }
        return await withResultTimeout { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)
                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }

                proxy.queryHistory(request: body) { data in
                    guard let data else {
                        safe.resume(returning: .failure(.decodingFailed("Missing lookup history response")))
                        return
                    }
                    do {
                        let response = try JSONDecoder().decode(
                            QueryHistoryResponse<Payload>.self,
                            from: data
                        )
                        safe.resume(returning: .success(response))
                    } catch {
                        safe.resume(returning: .failure(.decodingFailed(error.localizedDescription)))
                    }
                }
            }
        }
    }

    /// `.success(false)` means the agent answered but the resolver did not
    /// confirm the clear. A failure means no answer arrived in time.
    func clearQueryHistory() async -> Result<Bool, XPCError> {
        await withResultTimeout(seconds: queryHistoryClearTimeout) { [self] in
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)
                guard
                    let proxy = self.getProxy(handler: { _ in
                        safe.resume(returning: .failure(.agentNotResponding))
                    })
                else {
                    safe.resume(returning: .failure(.agentNotResponding))
                    return
                }
                proxy.clearQueryHistory { cleared in
                    safe.resume(returning: .success(cleared))
                }
            }
        }
    }

    // MARK: - License Management

    func deactivateLicense(completion: @escaping (Bool) -> Void) {
        getProxy { _ in completion(false) }?.deactivateLicense { success in
            DispatchQueue.main.async { completion(success) }
        }
    }

    func validateLicense(completion: @escaping (LicenseInfo?) -> Void) {
        getProxy { _ in completion(nil) }?.validateLicense { data in
            DispatchQueue.main.async {
                guard let data = data,
                    let info = try? JSONCoding.decoder.decode(LicenseInfo.self, from: data)
                else {
                    completion(nil)
                    return
                }
                completion(info)
            }
        }
    }

    // MARK: - Update Management

    /// The agent's cached update info, without a network call.
    func getUpdateInfo() async -> UpdateInfo? {
        await withTimeout {
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard let proxy = self.getProxy(handler: { _ in safe.resume(returning: nil) }) else {
                    safe.resume(returning: nil)
                    return
                }
                proxy.getUpdateInfo { data in
                    guard let data = data,
                        let info = try? JSONDecoder().decode(UpdateInfo.self, from: data)
                    else {
                        safe.resume(returning: nil)
                        return
                    }
                    safe.resume(returning: info)
                }
            }
        }
    }

    /// Asks the agent to check over the network now, with a longer timeout.
    func checkForUpdatesNow() async -> UpdateInfo? {
        await withTimeout(seconds: 30) {
            await withCheckedContinuation { continuation in
                let safe = SafeContinuation(continuation)

                guard let proxy = self.getProxy(handler: { _ in safe.resume(returning: nil) }) else {
                    safe.resume(returning: nil)
                    return
                }
                proxy.checkForUpdatesNow { data in
                    guard let data = data,
                        let info = try? JSONDecoder().decode(UpdateInfo.self, from: data)
                    else {
                        safe.resume(returning: nil)
                        return
                    }
                    safe.resume(returning: info)
                }
            }
        }
    }
}
