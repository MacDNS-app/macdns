// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import IOKit
import Shared

// MARK: - Admission Decision

/// Deadline-bound admission decision produced by a validation attempt.
///
/// A positive decision always carries the instant it stops being valid, so an
/// admission granted under offline grace can never outlive the effective
/// deadline while waiting for the next scheduled validation.
struct LicenseAdmissionDecision: Equatable, Sendable {
    let allowed: Bool
    let expiresAt: Date?

    static let denied = LicenseAdmissionDecision(allowed: false, expiresAt: nil)

    static func granted(until deadline: Date) -> LicenseAdmissionDecision {
        LicenseAdmissionDecision(allowed: true, expiresAt: deadline)
    }
}

extension LicenseState {
    /// Rests the state on a verified answer: its signed time and, when it is a
    /// `validate-key` answer, the answer itself. Any other answer leaves no
    /// receipt, so the state cannot run offline until the key is validated
    /// again.
    fileprivate mutating func rest(on evidence: AuthoritativeEvidence) {
        lastValidatedAt = evidence.serverTime
        validationReceipt = evidence.receipt
    }
}

// MARK: - License State Actor

private actor LicenseStateActor {
    var state: LicenseState
    var isValidating: Bool = false
    var admissionDecision: LicenseAdmissionDecision?
    var admissionJournalArmed = false
    var admissionRecoveryRequired = false
    var machineIdentityUnavailable = false

    init() {
        self.state = LicenseState()
    }

    func getState() -> LicenseState {
        return state
    }

    func setState(_ newState: LicenseState) {
        state = newState
    }

    func updateState(_ update: (inout LicenseState) -> Void) {
        update(&state)
    }

    func getIsValidating() -> Bool {
        return isValidating
    }

    func getAdmissionDecision() -> LicenseAdmissionDecision? {
        admissionDecision
    }

    func setAdmissionDecision(_ decision: LicenseAdmissionDecision?) {
        admissionDecision = decision
    }

    /// Resolves the recorded decision at `now`.
    ///
    /// Returns nil when no decision applies and the persisted state decides. An
    /// expired positive decision denies instead of falling through, otherwise the
    /// persisted state would silently re-admit service past its deadline.
    func resolveAdmission(now: Date) -> Bool? {
        guard let decision = admissionDecision else { return nil }
        guard decision.allowed else { return false }
        guard let expiresAt = decision.expiresAt else { return false }
        return now < expiresAt
    }

    func didArmAdmissionJournal() {
        admissionJournalArmed = true
    }

    func didClearAdmissionJournal() {
        admissionJournalArmed = false
    }

    func requireAdmissionRecovery() {
        admissionRecoveryRequired = true
    }

    func completeAdmissionRecovery() {
        admissionJournalArmed = false
        admissionRecoveryRequired = false
    }

    func getAdmissionJournalArmed() -> Bool {
        admissionJournalArmed
    }

    func getAdmissionRecoveryRequired() -> Bool {
        admissionRecoveryRequired
    }

    func setMachineIdentityUnavailable(_ unavailable: Bool) {
        machineIdentityUnavailable = unavailable
    }

    func getMachineIdentityUnavailable() -> Bool {
        machineIdentityUnavailable
    }

    /// Runs `operation` under the validation gate.
    ///
    /// Returns nil when another validation already holds the gate. The gate is
    /// released by `defer`, so an early exit can never wedge later validations.
    func runValidationTransaction<T: Sendable>(
        _ operation: @escaping @Sendable () async -> T
    ) async -> T? {
        guard !isValidating else { return nil }
        isValidating = true
        defer { isValidating = false }
        return await operation()
    }
}

private actor LicenseInitializationGate {
    private var task: Task<Void, Never>?

    func run(
        _ operation: @escaping @Sendable () async -> Void
    ) async {
        if let task {
            await task.value
            return
        }
        let task = Task {
            await operation()
        }
        self.task = task
        await task.value
    }
}

// MARK: - License Manager

final class LicenseManager: Sendable {

    // MARK: - Keygen.sh Configuration

    enum KeygenConfig {
        static let accountId = "07ef1cef-27fc-4e94-970a-7c5e89201289"

        // Trial policy for creating trial licenses.
        static let trialPolicyId = "f84203af-417a-4337-9153-2124fdcc2ca8"

        /// Info.plist key the build fills from `KEYGEN_TRIAL_TOKEN`. The token
        /// never lives in the repository. A build without it cannot create
        /// trials. A release build fails without it.
        static let trialTokenInfoKey = "KeygenTrialToken"
        static let trialToken = trialToken(from: Bundle.main.infoDictionary)

        static func trialToken(from info: [String: Any]?) -> String? {
            guard
                let token = info?[trialTokenInfoKey] as? String,
                !token.isEmpty,
                !token.hasPrefix("@@")
            else {
                return nil
            }
            return token
        }

        // Paid product scope for validate-key, a public endpoint without a token.
        static let productId = "b2ace9b9-0a7e-43ca-8866-be62d6ec80e0"

        static var baseURL: String {
            "https://api.keygen.sh/v1/accounts/\(accountId)"
        }
    }

    private static let validateKeyURL = URL(
        string: "\(KeygenConfig.baseURL)/licenses/actions/validate-key"
    )!

    // MARK: - Constants

    private enum Constants {
        static let trialDuration: TimeInterval = 7 * 24 * 60 * 60
        static let validationInterval: TimeInterval = 2 * 60 * 60
        static let gracePeriod: TimeInterval = 72 * 60 * 60
        static let validationWaitTimeout = LicenseRequestBudget.operation
    }

    // MARK: - Singleton

    static let shared = LicenseManager()

    // MARK: - Properties

    private let stateActor = LicenseStateActor()
    private let initializationGate = LicenseInitializationGate()
    private let failClosedLatch: LicenseFailClosedLatch
    private let session: URLSession
    private let licensePath: URL
    private let stateStore: LicenseStateFileStore
    private let validationWaitTimeout: TimeInterval
    private let fingerprintProvider: @Sendable () async -> String?
    private let verifier: LicenseResponseVerifier
    private let trustedClock: LicenseTrustedClock
    private let retryController: LicenseRetryController
    private let trialToken: String?

    private struct NotificationState {
        var lastNotifiedStatus: LicenseStatus?
        var lastNotifiedAllowed: Bool?
        var onStatusChange: ((LicenseStatus, Bool) -> Void)?
    }
    private let notificationLock = NSLock()
    // Safe: all access is serialized via notificationLock
    private nonisolated(unsafe) var _notificationState = NotificationState()
    // Safe: all access is serialized via DispatchQueue.main
    private nonisolated(unsafe) var _validationTimer: Timer?
    private let cachedAdmissionLock = NSLock()
    // Safe: all access is serialized via cachedAdmissionLock
    private nonisolated(unsafe) var _cachedAdmission = false
    private let servicesRunningLock = NSLock()
    // Safe: all access is serialized via servicesRunningLock
    private nonisolated(unsafe) var _servicesRunning = false
    /// Deadline of the latest validation-timer request, kept while services are
    /// stopped so starting them arms for it. Serialized via servicesRunningLock.
    private nonisolated(unsafe) var _requestedValidationDeadline: Date?

    private func withNotificationState<T>(_ body: (inout NotificationState) -> T) -> T {
        notificationLock.lock()
        defer { notificationLock.unlock() }
        return body(&_notificationState)
    }

    var onStatusChange: ((LicenseStatus, Bool) -> Void)? {
        get { withNotificationState { $0.onStatusChange } }
        set { withNotificationState { $0.onStatusChange = newValue } }
    }

    // MARK: - Initialization

    private convenience init() {
        self.init(
            session: LicenseManager.makeLicenseSession(),
            licensePath: PathResolver.licenseFile,
            validationWaitTimeout: Constants.validationWaitTimeout,
            fingerprintProvider: {
                await LicenseManager.systemMachineFingerprint()
            }
        )
    }

    /// Ephemeral, no-cache session. License traffic must never be served from a
    /// cache, and every request ends within `LicenseRequestBudget.perRequest`,
    /// because the XPC handlers reply from these requests.
    static func makeLicenseSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.timeoutIntervalForRequest = LicenseRequestBudget.perRequest
        configuration.timeoutIntervalForResource = LicenseRequestBudget.perRequest
        return URLSession(configuration: configuration)
    }

    init(
        session: URLSession,
        licensePath: URL,
        validationWaitTimeout: TimeInterval? = nil,
        fingerprintProvider: @escaping @Sendable () async -> String?,
        verifier: LicenseResponseVerifier? = nil,
        retryPolicy: LicenseRetryPolicy = LicenseRetryPolicy(),
        wallClock: @escaping @Sendable () -> Date = { Date() },
        monotonicClock: @escaping @Sendable () -> TimeInterval = {
            Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
        },
        trialToken: String? = KeygenConfig.trialToken
    ) {
        self.session = session
        self.licensePath = licensePath
        let stateStore = LicenseStateFileStore(path: licensePath)
        self.stateStore = stateStore
        self.failClosedLatch = LicenseFailClosedLatch(store: stateStore)
        self.validationWaitTimeout =
            validationWaitTimeout ?? Constants.validationWaitTimeout
        self.fingerprintProvider = fingerprintProvider
        self.verifier =
            verifier ?? LicenseResponseVerifier(accountId: KeygenConfig.accountId)
        self.trustedClock = LicenseTrustedClock(
            store: stateStore,
            wallClock: wallClock,
            uptime: monotonicClock
        )
        self.retryController = LicenseRetryController(policy: retryPolicy)
        self.trialToken = trialToken
        // The actor starts empty. initialize() loads state from disk.
    }

    // MARK: - Public Interface

    /// Loads state from disk. Does NOT validate or create a trial.
    func initialize() async {
        await initializationGate.run { [self] in
            AgentLogger.shared.info("Initializing license manager...")
            if !verifier.isConfigured {
                AgentLogger.shared.error(
                    "Keygen account verify key is not configured: license responses cannot be trusted"
                )
            }
            trustedClock.restore()
            await restoreFailClosedLatch()
            await restoreAdmissionJournal()
            _ = await loadState()
            let currentState = await stateActor.getState()
            AgentLogger.shared.notice(
                "License state loaded: \(currentState.status.rawValue)"
            )
        }
    }

    /// Returns whether service may start. Creates a trial on first run (no
    /// license to validate) and validates otherwise.
    ///
    /// - Nothing to validate: register a trial. Only a verified response persists.
    /// - License present: validate with API
    ///   - Verified success: allow services
    ///   - Transport/protocol failure: bounded grace, retry stays armed
    ///   - Verified expired/invalid: block services
    func ensureValidLicense() async -> Bool {
        await initialize()
        guard
            let result = await stateActor.runValidationTransaction({ [self] in
                await performEnsureValidLicenseLogic()
            })
        else {
            AgentLogger.shared.debug("License validation already in progress, waiting...")
            return await awaitConcurrentValidation()
        }
        return publishAdmission(result)
    }

    private func awaitConcurrentValidation() async -> Bool {
        let startTime = Date()
        while await stateActor.getIsValidating() {
            if Date().timeIntervalSince(startTime) > validationWaitTimeout {
                AgentLogger.shared.warning("Timeout waiting for concurrent license validation")
                return publishAdmission(false)
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return await currentAdmission()
    }

    private func performEnsureValidLicenseLogic() async -> Bool {
        AgentLogger.shared.info("Checking license before starting service...")

        guard FileManager.default.fileExists(atPath: licensePath.path) else {
            return await registerTrial()
        }

        switch await loadState() {
        case .absent:
            return await registerTrial()
        case .untrusted:
            AgentLogger.shared.error("Cannot validate license: persisted state is untrusted")
            return false
        case .loaded:
            break
        }

        let currentState = await stateActor.getState()

        // A state without any license reference cannot be validated. It is what an
        // offline first trial registration used to leave behind, so trial
        // onboarding resumes instead of latching a verdict that was never served.
        if currentState.licenseKey == nil && currentState.licenseId == nil {
            return await registerTrial()
        }

        if currentState.deactivationPending == true {
            _ = await completePendingDeactivation(currentState)
            return false
        }

        let requiresAdmissionJournal =
            currentState.licenseKey != nil || currentState.licenseId != nil
        if requiresAdmissionJournal {
            guard await beginAdmissionTransaction() else { return false }
        }

        AgentLogger.shared.debug("License found, validating with API...")

        // The API is the source of truth, so always validate.
        let validationResult = await validateStateWithAPI(currentState)

        switch validationResult {
        case .success(let expiresAt, let machineId, let evidence):
            await stateActor.updateState { state in
                state.rest(on: evidence)
                let isTrial = state.licenseId != nil && state.licenseKey == nil
                state.status = isTrial ? .trial : .valid
                state.expiresAt = expiresAt
                if let machineId {
                    state.machineId = machineId
                    state.machineReactivationPending = false
                }
            }
            guard await saveState() else {
                await handlePersistenceFailure(restoring: currentState)
                return false
            }
            guard
                await completeAuthoritativePersistence(
                    .verified(evidence),
                    clearingAdmissionJournal: requiresAdmissionJournal
                )
            else {
                return false
            }
            await startValidationTimer(deadline: expiresAt)
            await notifyStatusChange(force: machineId != nil)
            AgentLogger.shared.notice("License validated successfully")
            return true

        case .networkError:
            if requiresAdmissionJournal {
                guard await completeAdmissionWithoutTransition() else {
                    return false
                }
            }
            return await handleNetworkErrorFallback()

        case .persistenceFailure:
            return false

        case .blocked(let reason):
            if requiresAdmissionJournal {
                guard await completeAdmissionWithoutTransition() else {
                    return false
                }
            }
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.error("License validation blocked: \(reason)")
            return false

        case .expired(let evidence):
            await updateStatusAndNotify(
                .expired,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("License expired (API confirmed)")
            return false

        case .trialExpired(let evidence):
            await updateStatusAndNotify(
                .trialExpired,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("Trial expired (API confirmed)")
            return false

        case .trialNotFound(let evidence):
            guard
                await forgetMissingTrial(
                    evidence: evidence,
                    clearingAdmissionJournal: requiresAdmissionJournal
                )
            else {
                return false
            }
            return await registerTrial()

        case .suspended(let evidence), .invalid(let evidence):
            await updateStatusAndNotify(
                .invalid,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("License invalid/suspended (API confirmed)")
            return false
        }
    }

    private func registerTrial() async -> Bool {
        AgentLogger.shared.info("No license to validate, creating trial...")
        let success = await startTrialAndWait()
        if success {
            await startValidationTimer(deadline: await stateActor.getState().expiresAt)
        }
        return success
    }

    /// Handle a transport or protocol failure during validation.
    ///
    /// The latest actor state is re-read here: a validation-side mutation (for
    /// example persisting `machineReactivationPending`) must be visible before
    /// grace is evaluated, otherwise a machine without a server seat would be
    /// admitted from a stale pre-mutation snapshot.
    private func handleNetworkErrorFallback() async -> Bool {
        let state = await stateActor.getState()

        guard !failClosedLatch.isEngaged else {
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.error(
                "Network grace blocked by license fail-closed latch"
            )
            await armLicenseRetry()
            return false
        }

        // Read before the clock: the signed date of the stored answer is a
        // floor for it.
        let proof = await offlineProof(for: state)

        guard let now = trustedNow() else {
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.error(
                "Network grace blocked: local clock is behind verified server time"
            )
            await armLicenseRetry()
            return false
        }

        // Only a non-pending license with a signed validation may run offline.
        guard
            let deadline = LicenseFailClosedPolicy.effectiveDeadline(
                for: state,
                proof: proof
            )
        else {
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.warning(
                "Network error but license state \(state.status.rawValue) cannot run offline - services blocked"
            )
            await armLicenseRetry()
            return false
        }

        if now < deadline {
            await stateActor.setAdmissionDecision(.granted(until: deadline))
            let hoursRemaining = LicenseFailClosedPolicy.graceHoursRemaining(
                state,
                proof: proof,
                now: now
            )
            AgentLogger.shared.warning(
                "Validation failed (network), within grace period (\(hoursRemaining)h remaining)")
            await startValidationTimer(deadline: deadline)
            return true
        }

        // Grace expired, or the license itself expired during grace.
        await engageFailClosed(.networkGraceExpired)
        await stateActor.setAdmissionDecision(.denied)
        AgentLogger.shared.error("Validation failed: network error and grace period expired")
        return false
    }

    /// What the stored `validate-key` answer proves about `state`. Nil when
    /// there is none, when it does not verify, or when it is about another
    /// license or machine.
    private func offlineProof(for state: LicenseState) async -> LicenseOfflineProof? {
        guard let receipt = state.validationReceipt else {
            AgentLogger.shared.warning(
                "No signed license validation is stored, so the license cannot run offline"
            )
            return nil
        }
        let evidence: AuthoritativeEvidence
        switch verifier.verify(stored: receipt, method: "POST", url: Self.validateKeyURL) {
        case .success(let verified):
            evidence = verified
        case .failure(let failure):
            AgentLogger.shared.error(
                "Stored license validation rejected: \(failure.description)"
            )
            return nil
        }
        trustedClock.acknowledge(stored: evidence)
        guard let fingerprint = await resolvedFingerprint() else {
            AgentLogger.shared.error(
                "Machine identity unavailable, so the stored license validation cannot be matched to this Mac"
            )
            return nil
        }
        guard
            let proof = Self.offlineProof(
                in: receipt.body,
                validatedAt: evidence.serverTime,
                licenseKey: state.licenseKey,
                fingerprint: fingerprint
            )
        else {
            AgentLogger.shared.error(
                "Stored license validation does not prove this machine's license"
            )
            return nil
        }
        return proof
    }

    private func updateStatusAndNotify(
        _ status: LicenseStatus,
        evidence: AuthoritativeEvidence,
        clearingAdmissionJournal: Bool = false
    ) async {
        let previousState = await stateActor.getState()
        await stateActor.updateState {
            $0.status = status
            $0.validationReceipt = evidence.receipt
        }
        guard await saveState() else {
            await handlePersistenceFailure(restoring: previousState)
            return
        }
        guard
            await completeAuthoritativePersistence(
                .verified(evidence),
                clearingAdmissionJournal: clearingAdmissionJournal
            )
        else { return }
        stopValidationTimer()
        await notifyStatusChange()
    }

    func getLicenseInfo() async -> LicenseInfo {
        await initialize()
        let currentState = await stateActor.getState()
        let isAllowed = await isServiceAllowed()
        return LicenseInfo(
            from: currentState,
            isServiceAllowed: isAllowed,
            blockReason: isAllowed ? nil : await blockReason()
        )
    }

    private func blockReason() async -> String? {
        var operationInterrupted = false
        if case .loaded = stateStore.loadAdmissionJournal() {
            operationInterrupted = true
        }
        // A verdict from Keygen moves the status to one that explains the
        // block. A denial that leaves it runnable or unknown had no answer.
        let status = await stateActor.getState().status
        let checkUnanswered =
            await stateActor.getAdmissionDecision() == .denied
            && (LicenseFailClosedPolicy.isRunnableStatus(status) || status == .unknown)
        return LicenseBlockReason.message(
            latch: failClosedLatch.reason,
            clockTrusted: trustedNow() != nil,
            licenseFileExists: FileManager.default.fileExists(atPath: licensePath.path),
            operationInterrupted: operationInterrupted,
            machineIdentityUnavailable: await stateActor.getMachineIdentityUnavailable(),
            checkUnanswered: checkUnanswered
        )
    }

    /// Includes the grace period.
    func isServiceAllowed() async -> Bool {
        await initialize()
        return await currentAdmission()
    }

    private func currentAdmission() async -> Bool {
        if let reason = failClosedLatch.reason {
            AgentLogger.shared.warning(
                "Service blocked by license fail-closed latch: \(reason.rawValue)"
            )
            return publishAdmission(false)
        }
        guard let now = trustedNow() else {
            AgentLogger.shared.error(
                "Service blocked: local clock is behind verified server time"
            )
            return publishAdmission(false)
        }
        if let decided = await stateActor.resolveAdmission(now: now) {
            return publishAdmission(decided)
        }
        let currentState = await stateActor.getState()
        return publishAdmission(checkServiceAllowed(for: currentState, now: now))
    }

    /// Last computed admission decision.
    ///
    /// Synchronous lifecycle paths read this snapshot instead of blocking on the
    /// license actor or on the network. An exported XPC object is serialized, so a
    /// blocking read would remove the whole App control channel.
    nonisolated func cachedServiceAllowed() -> Bool {
        cachedAdmissionLock.lock()
        defer { cachedAdmissionLock.unlock() }
        return _cachedAdmission
    }

    @discardableResult
    private func publishAdmission(_ allowed: Bool) -> Bool {
        cachedAdmissionLock.lock()
        _cachedAdmission = allowed
        cachedAdmissionLock.unlock()
        return allowed
    }

    /// Awaits the in-flight license retry loop, if any.
    func waitForPendingRetry() async {
        await retryController.waitForCompletion()
    }

    private func checkServiceAllowed(for state: LicenseState, now: Date) -> Bool {
        // API-confirmed expired or invalid states never get a grace period.
        // Grace applies only to transport failures during validation.
        LicenseFailClosedPolicy.allowsService(state, now: now)
    }

    // MARK: - Trusted Clock

    /// Trusted instant for licensing decisions, or nil when the local clock is
    /// behind verified server time and must not be used to grant time.
    private func trustedNow() -> Date? {
        trustedClock.now().date
    }

    // MARK: - Date Parsing Helpers

    /// Accepts ISO 8601 with or without fractional seconds.
    private static func parseISO8601Date(_ string: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: string) {
            return date
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: string)
    }

    // MARK: - Unified API Validation

    private func validateStateWithAPI(_ state: LicenseState) async -> ValidationResult {
        guard state.deactivationPending != true else {
            return .blocked("License deactivation is pending")
        }

        // Trials, including expired ones and invalid ones with a licenseId, are
        // looked up again so a trial extension or reactivation is detected.
        let isTrialLicense =
            state.status == .trial || state.status == .trialExpired
            || (state.status == .invalid && state.licenseId != nil && state.licenseKey == nil)
        if isTrialLicense {
            switch await lookupTrialWithAPI() {
            case .active(_, let expiresAt, let evidence):
                return .success(
                    expiresAt: expiresAt,
                    machineId: nil,
                    evidence: evidence
                )
            case .ended(_, let evidence):
                return .trialExpired(evidence)
            case .notFound(let evidence):
                return .trialNotFound(evidence)
            case .networkError(let message):
                AgentLogger.shared.warning("Trial status check failed: \(message)")
                return .networkError
            }
        }

        if let licenseKey = state.licenseKey {
            let result = await validateKeyWithAPI(key: licenseKey)

            switch result {
            case .valid(let licenseId, let expiresAt, let evidence):
                // Expiry is judged against signed server time, never the local
                // wall clock. A forward clock jump must not manufacture expiry.
                if let expiry = expiresAt, evidence.serverTime >= expiry {
                    return .expired(evidence)
                }
                if state.machineReactivationPending == true {
                    return await reactivateMachineForValidation(
                        licenseKey: licenseKey,
                        licenseId: licenseId,
                        expiresAt: expiresAt,
                        validated: evidence
                    )
                }
                return .success(
                    expiresAt: expiresAt,
                    machineId: nil,
                    evidence: evidence
                )

            case .machineActivationRequired(let licenseId, let expiresAt, _):
                return await reactivateMachineForValidation(
                    licenseKey: licenseKey,
                    licenseId: licenseId,
                    expiresAt: expiresAt
                )

            case .expired(let evidence):
                return .expired(evidence)

            case .suspended(let evidence):
                return .suspended(evidence)

            case .invalid(let evidence):
                return .invalid(evidence)

            case .networkError:
                return .networkError
            }
        }

        // No license reference to validate. No request was made, so no verdict
        // exists: stay blocked instead of persisting one.
        return .blocked("No license key or trial to validate")
    }

    /// `validated` is the valid answer that asked for the reactivation, if any.
    private func reactivateMachineForValidation(
        licenseKey: String,
        licenseId: String,
        expiresAt: Date?,
        validated: AuthoritativeEvidence? = nil
    ) async -> ValidationResult {
        let previousState = await stateActor.getState()
        await stateActor.updateState { state in
            state.licenseId = licenseId
            state.machineId = nil
            state.machineReactivationPending = true
            state.validationReceipt = nil
        }
        guard await saveState() else {
            await handlePersistenceFailure(restoring: previousState)
            return .persistenceFailure
        }

        switch await activateMachineWithAPI(
            licenseKey: licenseKey,
            licenseId: licenseId
        ) {
        case .success(let machineId, let activation),
            .alreadyActivated(let machineId, let activation):
            switch await verdictOnActivatedKey(
                licenseKey, standing: validated ?? activation, expiresAt: expiresAt)
            {
            case .stands(let evidence, let expiresAt):
                return .success(
                    expiresAt: expiresAt,
                    machineId: machineId,
                    evidence: evidence
                )
            case .rejected(.invalid, let evidence):
                return .invalid(evidence)
            case .rejected(.expired, let evidence):
                return .expired(evidence)
            case .rejected(.suspended, let evidence):
                return .suspended(evidence)
            }
        case .networkError, .unrecognizedRejection:
            return .networkError
        case .machineLimit(_, let evidence),
            .error(_, let evidence):
            return .invalid(evidence)
        }
    }

    /// A signed answer that rejects a license key.
    private enum KeyRejection {
        case invalid
        case expired
        case suspended
    }

    private enum ActivatedKeyVerdict {
        /// The seat stands, on the key's valid answer when one came, else on
        /// the evidence it stood on. `expiresAt` comes from the same answer.
        case stands(AuthoritativeEvidence, expiresAt: Date?)
        case rejected(KeyRejection, AuthoritativeEvidence)
    }

    /// A machine answer cannot be stored as a receipt. Once the seat exists the
    /// key is validated again, so the state rests on an answer that can run
    /// offline. A signed rejection decides, as in any validation. `NO_MACHINE`
    /// or no answer keeps `standing` and `expiresAt`: the valid answer that
    /// started the same operation when there was one, so a receipt is never
    /// lost, else the activation answer, and the next validation brings the
    /// receipt.
    private func verdictOnActivatedKey(
        _ key: String,
        standing: AuthoritativeEvidence,
        expiresAt: Date?
    ) async -> ActivatedKeyVerdict {
        switch await validateKeyWithAPI(key: key) {
        case .valid(_, let renewedExpiry, let evidence):
            return .stands(evidence, expiresAt: renewedExpiry)
        case .machineActivationRequired, .networkError:
            return .stands(standing, expiresAt: expiresAt)
        case .invalid(let evidence):
            return .rejected(.invalid, evidence)
        case .expired(let evidence):
            return .rejected(.expired, evidence)
        case .suspended(let evidence):
            return .rejected(.suspended, evidence)
        }
    }

    func activateLicense(key: String) async -> LicenseActivationResult {
        await initialize()
        guard
            let result = await stateActor.runValidationTransaction({ [self] in
                await performActivation(key: key)
            })
        else {
            return .error(message: "License operation already in progress")
        }
        return result
    }

    private func performActivation(key: String) async -> LicenseActivationResult {
        AgentLogger.shared.info("Attempting to activate license...")

        guard await beginAdmissionTransaction() else {
            return .error(message: "Failed to start durable license operation")
        }
        let installedKey = await stateActor.getState().licenseKey

        let validationResult = await validateKeyWithAPI(key: key)

        switch validationResult {
        case .valid(let licenseId, let validatedExpiry, _),
            .machineActivationRequired(let licenseId, let validatedExpiry, _):
            let validated: AuthoritativeEvidence? =
                if case .valid(_, _, let evidence) = validationResult { evidence } else { nil }
            let activationResult = await activateMachineWithAPI(
                licenseKey: key, licenseId: licenseId)

            switch activationResult {
            case .success(let machineId, let activation):
                let evidence: AuthoritativeEvidence
                let expiresAt: Date?
                switch await verdictOnActivatedKey(
                    key, standing: validated ?? activation, expiresAt: validatedExpiry)
                {
                case .stands(let answer, let expiry):
                    evidence = answer
                    expiresAt = expiry
                case .rejected(let rejection, let answer):
                    return await rejectActivation(
                        rejection, evidence: answer, key: key, installedKey: installedKey)
                }
                let previousState = await stateActor.getState()
                await stateActor.updateState { state in
                    state.licenseKey = key
                    state.licenseId = licenseId
                    state.machineId = machineId
                    state.status = .valid
                    state.expiresAt = expiresAt
                    state.rest(on: evidence)
                    state.deactivationPending = false
                    state.machineReactivationPending = false
                }

                guard await saveState() else {
                    await handlePersistenceFailure(restoring: previousState)
                    return .error(message: "Failed to save license state")
                }
                guard
                    await completeAuthoritativePersistence(
                        .verified(evidence),
                        clearingAdmissionJournal: true
                    )
                else {
                    return .error(message: "Failed to complete durable license operation")
                }
                await startValidationTimer(deadline: expiresAt)
                await notifyStatusChange()

                AgentLogger.shared.notice("License activated successfully")
                return .success(message: "License activated successfully")

            case .alreadyActivated(let machineId, let activation):
                let evidence: AuthoritativeEvidence
                let expiresAt: Date?
                switch await verdictOnActivatedKey(
                    key, standing: validated ?? activation, expiresAt: validatedExpiry)
                {
                case .stands(let answer, let expiry):
                    evidence = answer
                    expiresAt = expiry
                case .rejected(let rejection, let answer):
                    return await rejectActivation(
                        rejection, evidence: answer, key: key, installedKey: installedKey)
                }
                let previousState = await stateActor.getState()
                await stateActor.updateState { state in
                    state.licenseKey = key
                    state.licenseId = licenseId
                    state.machineId = machineId
                    state.status = .valid
                    state.expiresAt = expiresAt
                    state.rest(on: evidence)
                    state.deactivationPending = false
                    state.machineReactivationPending = false
                }

                guard await saveState() else {
                    await handlePersistenceFailure(restoring: previousState)
                    return .error(message: "Failed to save license state")
                }
                guard
                    await completeAuthoritativePersistence(
                        .verified(evidence),
                        clearingAdmissionJournal: true
                    )
                else {
                    return .error(message: "Failed to complete durable license operation")
                }
                await startValidationTimer(deadline: expiresAt)
                await notifyStatusChange()

                return .alreadyActivated

            case .machineLimit(let limit, _):
                guard await completeAdmissionWithoutTransition() else {
                    return .error(message: "Failed to complete durable license operation")
                }
                return .machineLimit(limit: limit)

            case .networkError(let message):
                guard await completeAdmissionWithoutTransition() else {
                    return .error(message: "Failed to complete durable license operation")
                }
                return .networkError(message: message)

            case .error(let message, _), .unrecognizedRejection(let message):
                guard await completeAdmissionWithoutTransition() else {
                    return .error(message: "Failed to complete durable license operation")
                }
                return .error(message: message)
            }

        case .invalid(let evidence):
            return await rejectActivation(
                .invalid, evidence: evidence, key: key, installedKey: installedKey)

        case .expired(let evidence):
            return await rejectActivation(
                .expired, evidence: evidence, key: key, installedKey: installedKey)

        case .suspended(let evidence):
            return await rejectActivation(
                .suspended, evidence: evidence, key: key, installedKey: installedKey)

        case .networkError(let message):
            guard await completeAdmissionWithoutTransition() else {
                return .error(message: "Failed to complete durable license operation")
            }
            return .networkError(message: message)
        }
    }

    private func rejectActivation(
        _ rejection: KeyRejection,
        evidence: AuthoritativeEvidence,
        key: String,
        installedKey: String?
    ) async -> LicenseActivationResult {
        guard
            await settleRejectedActivation(
                key: key,
                installedKey: installedKey,
                status: rejection == .expired ? .expired : .invalid,
                evidence: evidence
            )
        else {
            return .error(message: "Failed to complete durable license operation")
        }
        switch rejection {
        case .invalid:
            return .invalidKey
        case .expired:
            return .error(message: "License has expired")
        case .suspended:
            return .error(message: "License has been suspended")
        }
    }

    /// A rejected key is only reported. Persisting it would replace a working
    /// trial or paid license with a key that can never be used. The installed
    /// key's own rejection is a verdict on the running license and is applied.
    private func settleRejectedActivation(
        key: String,
        installedKey: String?,
        status: LicenseStatus,
        evidence: AuthoritativeEvidence
    ) async -> Bool {
        guard key == installedKey else {
            return await completeAdmissionWithoutTransition()
        }
        AgentLogger.shared.warning("Installed license key was rejected: \(status.rawValue)")
        await updateStatusAndNotify(status, evidence: evidence, clearingAdmissionJournal: true)
        return true
    }

    func deactivateLicense() async -> Bool {
        await initialize()
        return await stateActor.runValidationTransaction { [self] in
            await performDeactivation()
        } ?? false
    }

    private func performDeactivation() async -> Bool {
        let currentState = await stateActor.getState()
        guard currentState.licenseKey != nil,
            currentState.machineId != nil
        else {
            return false
        }

        var pendingState = currentState
        pendingState.status = .invalid
        pendingState.deactivationPending = true
        pendingState.validationReceipt = nil
        await stateActor.setState(pendingState)
        guard await saveState() else {
            await handlePersistenceFailure(restoring: currentState)
            return false
        }

        await stateActor.setAdmissionDecision(nil)
        stopValidationTimer()
        await notifyStatusChange()
        return await completePendingDeactivation(pendingState)
    }

    private func completePendingDeactivation(
        _ pendingState: LicenseState
    ) async -> Bool {
        guard
            let licenseKey = pendingState.licenseKey,
            let machineId = pendingState.machineId
        else {
            return await finalizeDeactivation(pendingState: pendingState)
        }

        guard
            await deactivateMachineWithAPI(
                licenseKey: licenseKey,
                machineId: machineId
            )
        else {
            return false
        }
        return await finalizeDeactivation(pendingState: pendingState)
    }

    private func finalizeDeactivation(
        pendingState: LicenseState
    ) async -> Bool {
        await stateActor.updateState { state in
            state.licenseKey = nil
            state.licenseId = nil
            state.machineId = nil
            state.status = .trialExpired
            state.expiresAt = nil
            state.lastValidatedAt = nil
            state.validationReceipt = nil
            state.deactivationPending = false
            state.machineReactivationPending = false
        }

        guard await saveState() else {
            await handlePersistenceFailure(restoring: pendingState)
            return false
        }
        // Explicit user deactivation only removes rights, so it needs no server
        // evidence to complete.
        guard
            await completeAuthoritativePersistence(
                .rightsReducing,
                clearingAdmissionJournal: true
            )
        else {
            return false
        }
        // The hardware ID no longer explains a block once no license is held.
        await stateActor.setMachineIdentityUnavailable(false)

        await notifyStatusChange()
        AgentLogger.shared.notice("License deactivated")
        return true
    }

    /// The App's Refresh. Without any license reference there is nothing to
    /// validate, so it runs the same trial resolution as Enable and a trial that
    /// was never registered is created here too.
    func validateLicense() async -> LicenseInfo {
        await initialize()
        let state = await stateActor.getState()
        if state.licenseKey == nil && state.licenseId == nil {
            _ = await ensureValidLicense()
        } else {
            await performValidation()
        }
        return await getLicenseInfo()
    }

    // MARK: - Trial Management

    /// Resolves this machine's trial and returns whether it admits service.
    ///
    /// The server is asked first, so a reinstall, a deleted license file or a
    /// create whose response was lost adopts the trial Keygen already holds
    /// instead of mistaking it for a used one. Only a verified lookup or create
    /// persists anything.
    private func startTrialAndWait() async -> Bool {
        guard await resolvedFingerprint() != nil else {
            AgentLogger.shared.error("Cannot start trial: machine identity unavailable")
            await stateActor.setAdmissionDecision(.denied)
            await armLicenseRetry()
            return false
        }

        switch await lookupTrialWithAPI() {
        case .active(let licenseId, let expiresAt, let evidence):
            AgentLogger.shared.notice("Existing trial found for this machine")
            return await adoptTrial(
                licenseId: licenseId,
                expiresAt: expiresAt,
                evidence: evidence
            )
        case .ended(let licenseId, let evidence):
            return await adoptEndedTrial(licenseId: licenseId, evidence: evidence)
        case .networkError(let message):
            return await deferTrialRegistration(message)
        case .notFound:
            break
        }

        guard let fingerprint = await resolvedFingerprint() else {
            return await deferTrialRegistration("Machine identity unavailable")
        }
        switch await registerTrialWithAPI(fingerprint: fingerprint) {
        case .success(let licenseId, let expiresAt, let evidence):
            AgentLogger.shared.notice("Trial started, expires at \(expiresAt)")
            // The create answer cannot be stored as a receipt, so the new trial
            // is looked up once for an answer that can run offline. A lookup
            // that finds it ended decides. No answer keeps the create answer.
            switch await lookupTrialWithAPI() {
            case .active(let licenseId, let expiresAt, let receipt):
                return await adoptTrial(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: receipt
                )
            case .ended(let licenseId, let receipt):
                return await adoptEndedTrial(licenseId: licenseId, evidence: receipt)
            case .notFound, .networkError:
                return await adoptTrial(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: evidence
                )
            }

        case .keyTaken:
            switch await lookupTrialWithAPI() {
            case .active(let licenseId, let expiresAt, let evidence):
                AgentLogger.shared.notice("Trial already registered for this machine")
                return await adoptTrial(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: evidence
                )
            case .ended(let licenseId, let evidence):
                return await adoptEndedTrial(licenseId: licenseId, evidence: evidence)
            case .notFound:
                return await deferTrialRegistration(
                    "Trial key is taken but no trial was found"
                )
            case .networkError(let message):
                return await deferTrialRegistration(message)
            }

        case .retryable(let message):
            return await deferTrialRegistration(message)
        }
    }

    /// The verified verdict is itself the authoritative transition, so it also
    /// finishes an operation interrupted before any license reference existed.
    private func adoptTrial(
        licenseId: String,
        expiresAt: Date?,
        evidence: AuthoritativeEvidence
    ) async -> Bool {
        let previousState = await stateActor.getState()
        await stateActor.updateState { state in
            state.status = .trial
            state.expiresAt = expiresAt
            state.licenseId = licenseId
            state.rest(on: evidence)
            state.deactivationPending = false
            state.machineReactivationPending = false
        }
        guard await saveState() else {
            await handlePersistenceFailure(restoring: previousState)
            return false
        }
        guard
            await completeAuthoritativePersistence(
                .verified(evidence),
                clearingAdmissionJournal: await stateActor.getAdmissionRecoveryRequired()
            )
        else {
            return false
        }
        await notifyStatusChange()
        return true
    }

    /// Keeps the license reference, so later checks look the trial up instead
    /// of trying to create it again.
    private func adoptEndedTrial(
        licenseId: String,
        evidence: AuthoritativeEvidence
    ) async -> Bool {
        AgentLogger.shared.warning("Trial for this machine has ended")
        let previousState = await stateActor.getState()
        await stateActor.updateState { state in
            state.status = .trialExpired
            state.licenseId = licenseId
            state.rest(on: evidence)
        }
        guard await saveState() else {
            await handlePersistenceFailure(restoring: previousState)
            return false
        }
        guard
            await completeAuthoritativePersistence(
                .verified(evidence),
                clearingAdmissionJournal: await stateActor.getAdmissionRecoveryRequired()
            )
        else {
            return false
        }
        await notifyStatusChange()
        return false
    }

    /// A transport or protocol failure is not a verdict. Nothing is persisted, so
    /// an offline first launch cannot destroy trial onboarding: the license-owned
    /// retry registers it later.
    private func deferTrialRegistration(_ message: String) async -> Bool {
        AgentLogger.shared.error("Trial registration unavailable: \(message)")
        await stateActor.setAdmissionDecision(.denied)
        await armLicenseRetry()
        return false
    }

    /// The trial this state refers to no longer exists on the server, for
    /// example because support deleted it. The reference is dropped under the
    /// verified lookup, so onboarding can register the machine again.
    private func forgetMissingTrial(
        evidence: AuthoritativeEvidence,
        clearingAdmissionJournal: Bool
    ) async -> Bool {
        AgentLogger.shared.warning("Trial no longer exists on the server")
        let previousState = await stateActor.getState()
        await stateActor.updateState { state in
            state.licenseId = nil
            state.status = .unknown
            state.expiresAt = nil
            state.rest(on: evidence)
        }
        guard await saveState() else {
            await handlePersistenceFailure(restoring: previousState)
            return false
        }
        return await completeAuthoritativePersistence(
            .verified(evidence),
            clearingAdmissionJournal: clearingAdmissionJournal
        )
    }

    // MARK: - Scheduled Validation

    private func performValidation() async {
        let performed =
            await stateActor.runValidationTransaction { [self] in
                await performValidationLogic()
            } != nil
        // The operation holding the gate may end without a verdict, and the
        // timer that called this is not rearmed, so the check runs later.
        guard performed else {
            AgentLogger.shared.info("License validation already in progress, retrying later")
            await armLicenseRetry()
            return
        }
    }

    private func performValidationLogic() async {
        let currentState = await stateActor.getState()
        let requiresAdmissionJournal =
            currentState.licenseKey != nil || currentState.licenseId != nil
        if requiresAdmissionJournal {
            guard await beginAdmissionTransaction() else { return }
        }

        // The API is the source of truth, so always validate.
        let validationResult = await validateStateWithAPI(currentState)

        switch validationResult {
        case .success(let expiresAt, let machineId, let evidence):
            let previousStatus = currentState.status
            await stateActor.updateState { state in
                state.rest(on: evidence)
                let isTrial = state.licenseId != nil && state.licenseKey == nil
                state.status = isTrial ? .trial : .valid
                state.expiresAt = expiresAt
                if let machineId {
                    state.machineId = machineId
                    state.machineReactivationPending = false
                }
            }
            guard await saveState() else {
                await handlePersistenceFailure(restoring: currentState)
                return
            }
            guard
                await completeAuthoritativePersistence(
                    .verified(evidence),
                    clearingAdmissionJournal: requiresAdmissionJournal
                )
            else { return }
            if previousStatus != .trial && previousStatus != .valid {
                AgentLogger.shared.notice("Scheduled validation: License renewed from \(previousStatus.rawValue)")
            } else {
                AgentLogger.shared.debug("Scheduled validation: Success")
            }
            await startValidationTimer(deadline: expiresAt)
            await notifyStatusChange(force: machineId != nil)

        case .networkError:
            if requiresAdmissionJournal {
                guard await completeAdmissionWithoutTransition() else {
                    return
                }
            }
            let allowed = await handleNetworkErrorFallback()
            if !allowed {
                await notifyStatusChange(force: true)
            }

        case .persistenceFailure:
            return

        case .blocked(let reason):
            if requiresAdmissionJournal {
                guard await completeAdmissionWithoutTransition() else {
                    return
                }
            }
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.error("Scheduled validation blocked: \(reason)")
            await notifyStatusChange(force: true)

        case .expired(let evidence):
            await updateStatusAndNotify(
                .expired,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("Scheduled validation: License expired")

        case .suspended(let evidence), .invalid(let evidence):
            await updateStatusAndNotify(
                .invalid,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("Scheduled validation: License invalid/suspended")

        case .trialExpired(let evidence):
            await updateStatusAndNotify(
                .trialExpired,
                evidence: evidence,
                clearingAdmissionJournal: requiresAdmissionJournal
            )
            AgentLogger.shared.warning("Scheduled validation: Trial expired")

        case .trialNotFound(let evidence):
            guard
                await forgetMissingTrial(
                    evidence: evidence,
                    clearingAdmissionJournal: requiresAdmissionJournal
                )
            else {
                return
            }
            if !(await registerTrial()) {
                await notifyStatusChange(force: true)
            }
        }
    }

    /// Schedules the next validation.
    ///
    /// Never later than `deadline`: a grace admission must be re-evaluated at the
    /// instant it stops being valid, not up to a whole validation interval later.
    private func startValidationTimer(deadline: Date? = nil) async {
        servicesRunningLock.withLock { _requestedValidationDeadline = deadline }
        let interval = LicenseValidationSchedule.nextInterval(
            now: trustedNow() ?? Date(),
            deadline: deadline,
            maxInterval: Constants.validationInterval
        )
        DispatchQueue.main.async { [weak self] in
            guard let self, self.areServicesRunning() else { return }
            self._validationTimer?.invalidate()
            self._validationTimer = Timer.scheduledTimer(
                withTimeInterval: interval, repeats: false
            ) { [weak self] _ in
                Task {
                    await self?.performValidation()
                }
            }
        }
    }

    /// Periodic validation (the Keygen callhome) runs only while the agent services run.
    /// Arming happens on the main queue, so a late arm cannot beat an earlier stop.
    /// Starting arms for the deadline the last validation requested (a grace
    /// deadline included), falling back to the license expiry.
    @discardableResult
    nonisolated func setServicesRunning(_ running: Bool) -> Task<Void, Never>? {
        let requestedDeadline = servicesRunningLock.withLock { () -> Date? in
            _servicesRunning = running
            return _requestedValidationDeadline
        }
        guard running else {
            stopValidationTimer()
            return nil
        }
        return Task {
            let deadline: Date?
            if let requestedDeadline {
                deadline = requestedDeadline
            } else {
                deadline = await stateActor.getState().expiresAt
            }
            await startValidationTimer(deadline: deadline)
        }
    }

    private nonisolated func areServicesRunning() -> Bool {
        servicesRunningLock.lock()
        defer { servicesRunningLock.unlock() }
        return _servicesRunning
    }

    func isValidationScheduled() async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { [weak self] in
                continuation.resume(returning: self?._validationTimer != nil)
            }
        }
    }

    private func stopValidationTimer() {
        DispatchQueue.main.async { [weak self] in
            self?._validationTimer?.invalidate()
            self?._validationTimer = nil
        }
    }

    // MARK: - License-Owned Retry

    /// Arms the license-owned bounded retry.
    ///
    /// Startup license failures happen before `NetworkMonitor` accepts callbacks,
    /// so recovery cannot depend on it. The retry only re-runs
    /// `ensureValidLicense()`. It never clears the fail-closed latch and never
    /// admits service by itself.
    private func armLicenseRetry() async {
        await retryController.arm { [weak self] in
            guard let self else { return true }
            return await self.retryValidLicense()
        }
    }

    /// One retry attempt. Unlike `ensureValidLicense()` it never adopts the
    /// outcome of another transaction holding the gate. An activation or a
    /// timeout says nothing about this resolution, so the loop asks for another
    /// attempt instead of ending.
    private func retryValidLicense() async -> Bool {
        await initialize()
        guard
            let result = await stateActor.runValidationTransaction({ [self] in
                await performEnsureValidLicenseLogic()
            })
        else {
            AgentLogger.shared.info("License retry deferred: another license operation is in progress")
            await armLicenseRetry()
            return false
        }
        let allowed = publishAdmission(result)
        // Nothing waits on a retry to start services, so its admission is
        // always reported. The last report can still say allowed: a denial
        // returned to `ensureValidLicense()` reports nothing.
        if allowed {
            await notifyStatusChange(force: true)
        }
        return allowed
    }

    // MARK: - Machine Fingerprint

    /// Machine identity for API requests, derived from the hardware on every
    /// call and never stored. See `MachineFingerprintPolicy`.
    private func resolvedFingerprint() async -> String? {
        let fingerprint = await fingerprintProvider()
        await stateActor.setMachineIdentityUnavailable(fingerprint == nil)
        return fingerprint
    }

    private static func systemMachineFingerprint() async -> String? {
        let resolution = await MachineFingerprintPolicy.resolve(
            read: { readHardwareIdentity() },
            sleep: { seconds in
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            }
        )
        switch resolution {
        case .fingerprint(let fingerprint):
            return fingerprint
        case .unreadable:
            AgentLogger.shared.error("Hardware identity could not be read: no machine fingerprint")
        case .unstable:
            AgentLogger.shared.error(
                "Hardware serial number appeared and disappeared between reads: no machine fingerprint"
            )
        }
        return nil
    }

    /// One snapshot of the platform expert, so an absent serial is told apart
    /// from a failed read. A serial that is not a string counts as absent, as
    /// it did in 1.x, since it is the same on every read.
    private static func readHardwareIdentity() -> HardwareIdentityReading? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }

        var unmanagedProperties: Unmanaged<CFMutableDictionary>?
        guard
            IORegistryEntryCreateCFProperties(
                platformExpert,
                &unmanagedProperties,
                kCFAllocatorDefault,
                0
            ) == KERN_SUCCESS,
            let properties = unmanagedProperties?.takeRetainedValue() as? [String: Any],
            let platformUUID = properties[kIOPlatformUUIDKey] as? String,
            let modelIdentifier = readModelIdentifier()
        else {
            return nil
        }
        let serial: HardwareIdentityReading.Serial
        if let value = properties[kIOPlatformSerialNumberKey] as? String {
            serial = .present(value)
        } else {
            serial = .absent
        }
        return HardwareIdentityReading(
            platformUUID: platformUUID,
            serial: serial,
            modelIdentifier: modelIdentifier
        )
    }

    private static func readModelIdentifier() -> String? {
        var size = 0
        guard sysctlbyname("hw.model", nil, &size, nil, 0) == 0, size > 0 else { return nil }

        var model = [CChar](repeating: 0, count: size)
        guard sysctlbyname("hw.model", &model, &size, nil, 0) == 0 else { return nil }
        return String(cString: model)
    }

    // MARK: - State Persistence

    private func restoreFailClosedLatch() async {
        switch stateStore.loadFailClosedState() {
        case .missing:
            return

        case .loaded(let persistedState):
            failClosedLatch.restore(persistedState)
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.warning(
                "Restored license fail-closed latch: \(persistedState.reason.rawValue)"
            )

        case .invalid(let reason):
            AgentLogger.shared.error(
                "License fail-closed state is invalid: \(reason)"
            )
            await engageFailClosed(.stateLoadFailed)
            await stateActor.setAdmissionDecision(.denied)

        case .ioFailure(let reason):
            AgentLogger.shared.error(
                "Failed to read license fail-closed state: \(reason)"
            )
            await engageFailClosed(.stateLoadFailed)
            await stateActor.setAdmissionDecision(.denied)
        }
    }

    private func restoreAdmissionJournal() async {
        switch stateStore.loadAdmissionJournal() {
        case .missing:
            return

        case .loaded(let entry):
            failClosedLatch.restore(
                LicenseFailClosedState(
                    reason: .statePersistenceFailed,
                    engagedAt: entry.armedAt
                )
            )
            await stateActor.didArmAdmissionJournal()
            await stateActor.requireAdmissionRecovery()
            await stateActor.setAdmissionDecision(.denied)
            AgentLogger.shared.warning(
                "Restored incomplete authoritative license operation in fail-closed mode"
            )

        case .invalid(let reason):
            AgentLogger.shared.error(
                "License admission journal is invalid: \(reason)"
            )
            await engageFailClosed(.stateLoadFailed)
            await stateActor.didArmAdmissionJournal()
            await stateActor.requireAdmissionRecovery()
            await stateActor.setAdmissionDecision(.denied)

        case .ioFailure(let reason):
            AgentLogger.shared.error(
                "Failed to read license admission journal: \(reason)"
            )
            await engageFailClosed(.stateLoadFailed)
            await stateActor.didArmAdmissionJournal()
            await stateActor.requireAdmissionRecovery()
            await stateActor.setAdmissionDecision(.denied)
        }
    }

    private enum StateLoadOutcome {
        case absent
        case loaded
        case untrusted
    }

    /// Loads persisted state.
    ///
    /// A corrupt or unreadable file latches fail-closed instead of silently
    /// becoming an empty state that would look like a fresh install.
    private func loadState() async -> StateLoadOutcome {
        switch stateStore.load() {
        case .missing:
            AgentLogger.shared.debug("No license file found, starting fresh")
            return .absent

        case .loaded(let loaded):
            await stateActor.setState(loaded)
            return .loaded

        case .invalid(let reason):
            AgentLogger.shared.error("License state is invalid: \(reason)")
            await engageFailClosed(.stateLoadFailed)
            await stateActor.setAdmissionDecision(.denied)
            return .untrusted

        case .ioFailure(let reason):
            AgentLogger.shared.error("Failed to read license state: \(reason)")
            await engageFailClosed(.stateLoadFailed)
            await stateActor.setAdmissionDecision(.denied)
            return .untrusted
        }
    }

    @discardableResult
    private func saveState() async -> Bool {
        let currentState = await stateActor.getState()
        guard stateStore.save(currentState) else {
            if await stateActor.getAdmissionJournalArmed() {
                await stateActor.requireAdmissionRecovery()
            }
            await engageFailClosed(.statePersistenceFailed)
            return false
        }
        AgentLogger.shared.debug("License state saved: \(currentState.status.rawValue)")
        return true
    }

    /// Only a check that persists clears the latch, and only the retry runs
    /// one on its own, so engaging it always leaves a retry armed.
    private func engageFailClosed(_ reason: LicenseFailClosedReason) async {
        if !failClosedLatch.engage(reason) {
            AgentLogger.shared.error(
                "Failed to persist license fail-closed latch: \(reason.rawValue)"
            )
        }
        await armLicenseRetry()
    }

    private func beginAdmissionTransaction() async -> Bool {
        guard
            stateStore.saveAdmissionJournal(
                LicenseAdmissionJournalEntry(armedAt: Date())
            )
        else {
            await handleAdmissionJournalFailure(
                "License operation blocked because its admission journal could not be persisted"
            )
            return false
        }
        await stateActor.didArmAdmissionJournal()
        return true
    }

    private func completeAdmissionWithoutTransition() async -> Bool {
        let currentState = await stateActor.getState()
        guard await saveState() else {
            await handlePersistenceFailure(restoring: currentState)
            return false
        }
        guard !(await stateActor.getAdmissionRecoveryRequired()) else {
            return true
        }
        guard stateStore.clearAdmissionJournal() else {
            await handleAdmissionJournalFailure(
                "License operation completed without a state transition, but its admission journal could not be cleared"
            )
            return false
        }
        await stateActor.didClearAdmissionJournal()
        return true
    }

    /// How a durable authoritative license transition is justified.
    private enum AuthoritativeTransition {
        /// Backed by a cryptographically verified server response.
        case verified(AuthoritativeEvidence)
        /// Explicit user deactivation. It only removes rights, so it needs no
        /// server evidence.
        case rightsReducing
    }

    private func completeAuthoritativePersistence(
        _ transition: AuthoritativeTransition,
        clearingAdmissionJournal: Bool = false
    ) async -> Bool {
        if clearingAdmissionJournal {
            guard stateStore.clearAdmissionJournal() else {
                await handleAdmissionJournalFailure(
                    "Authoritative license state persisted, but its admission journal could not be cleared"
                )
                return false
            }
        } else {
            switch stateStore.loadAdmissionJournal() {
            case .missing:
                break
            case .loaded:
                await handleAdmissionJournalFailure(
                    "Authoritative license transition cannot clear an incomplete license operation"
                )
                return false
            case .invalid(let reason), .ioFailure(let reason):
                await handleAdmissionJournalFailure(
                    "Authoritative license transition could not verify the admission journal: \(reason)"
                )
                return false
            }
        }

        let cleared: Bool
        switch transition {
        case .verified(let evidence):
            // The trusted-time high-water mark is part of the transition. Losing
            // it would let a later rollback re-admit this very state.
            guard trustedClock.record(evidence) else {
                await engageFailClosed(.statePersistenceFailed)
                await stateActor.setAdmissionDecision(.denied)
                stopValidationTimer()
                AgentLogger.shared.error(
                    "Authoritative license state persisted, but the trusted time high-water mark could not be recorded"
                )
                await notifyStatusChange(force: true)
                return false
            }
            cleared = failClosedLatch.clearForAuthoritativeTransition(
                evidence: evidence
            )
        case .rightsReducing:
            cleared = failClosedLatch.clearForRightsReducingTransition()
        }

        guard cleared else {
            await stateActor.setAdmissionDecision(.denied)
            stopValidationTimer()
            AgentLogger.shared.error(
                "Authoritative license state persisted, but fail-closed latch could not be cleared"
            )
            await notifyStatusChange(force: true)
            await armLicenseRetry()
            return false
        }
        if clearingAdmissionJournal {
            await stateActor.completeAdmissionRecovery()
        }
        await stateActor.setAdmissionDecision(nil)
        return true
    }

    private func handleAdmissionJournalFailure(_ message: String) async {
        await engageFailClosed(.statePersistenceFailed)
        await stateActor.requireAdmissionRecovery()
        await stateActor.setAdmissionDecision(.denied)
        stopValidationTimer()
        AgentLogger.shared.error(message)
        await notifyStatusChange(force: true)
    }

    private func handlePersistenceFailure(
        restoring previousState: LicenseState
    ) async {
        await stateActor.setState(previousState)
        await stateActor.setAdmissionDecision(.denied)
        stopValidationTimer()
        await notifyStatusChange(force: true)
    }

    // MARK: - Status Change Notification

    private func notifyStatusChange(force: Bool = false) async {
        let currentState = await stateActor.getState()
        let isAllowed: Bool
        if failClosedLatch.isEngaged {
            isAllowed = false
        } else if let now = trustedNow() {
            isAllowed =
                await stateActor.resolveAdmission(now: now)
                ?? checkServiceAllowed(for: currentState, now: now)
        } else {
            isAllowed = false
        }
        publishAdmission(isAllowed)

        let (shouldNotify, callback) = withNotificationState { state in
            guard
                force
                    || currentState.status != state.lastNotifiedStatus
                    || isAllowed != state.lastNotifiedAllowed
            else {
                return (false, nil as ((LicenseStatus, Bool) -> Void)?)
            }
            state.lastNotifiedStatus = currentState.status
            state.lastNotifiedAllowed = isAllowed
            return (true, state.onStatusChange)
        }

        if shouldNotify {
            callback?(currentState.status, isAllowed)
        }
    }

    // MARK: - Validation Result (for ensureValidLicense flow)

    private enum ValidationResult {
        case success(
            expiresAt: Date?,
            machineId: String?,
            evidence: AuthoritativeEvidence
        )
        case networkError
        case persistenceFailure
        /// No verdict exists, because no request was made or the local state
        /// cannot be validated. Nothing may be persisted from this outcome.
        case blocked(String)
        case expired(AuthoritativeEvidence)
        case invalid(AuthoritativeEvidence)
        case suspended(AuthoritativeEvidence)
        case trialExpired(AuthoritativeEvidence)
        case trialNotFound(AuthoritativeEvidence)
    }

    // MARK: - Keygen.sh API

    /// Semantic verdict parsed out of an already verified validate-key response.
    enum KeyValidationVerdict: Equatable {
        case valid(licenseId: String, expiresAt: Date?)
        case machineActivationRequired(licenseId: String, expiresAt: Date?)
        case invalid
        case expired
        case suspended
        /// Transport or protocol problem. Retryable, never a verdict.
        case protocolFailure(String)
    }

    enum KeyValidationResult {
        case valid(
            licenseId: String,
            expiresAt: Date?,
            evidence: AuthoritativeEvidence
        )
        case machineActivationRequired(
            licenseId: String,
            expiresAt: Date?,
            evidence: AuthoritativeEvidence
        )
        case invalid(evidence: AuthoritativeEvidence)
        case expired(evidence: AuthoritativeEvidence)
        case suspended(evidence: AuthoritativeEvidence)
        case networkError(String)
    }

    private enum MachineActivationResult {
        case success(machineId: String, evidence: AuthoritativeEvidence)
        case alreadyActivated(machineId: String, evidence: AuthoritativeEvidence)
        case machineLimit(limit: Int, evidence: AuthoritativeEvidence)
        /// A 422 whose error codes are not a known seat verdict.
        case unrecognizedRejection(String)
        case networkError(String)
        case error(String, evidence: AuthoritativeEvidence)
    }

    private enum ExistingMachineLookupResult {
        case found(machineId: String, evidence: AuthoritativeEvidence)
        case notFound
        case networkError(String)
    }

    private enum TrialRegistrationResult {
        case success(
            licenseId: String,
            expiresAt: Date,
            evidence: AuthoritativeEvidence
        )
        /// Keygen already holds a license keyed by this fingerprint, typically
        /// from an earlier create whose response never arrived.
        case keyTaken
        case retryable(String)
    }

    /// Semantic verdict of the trial lookup by machine fingerprint, parsed out of
    /// an already verified validate-key response.
    enum TrialLookupVerdict: Equatable {
        /// No license carries this fingerprint as its key, so a trial may be created.
        case notFound
        case active(licenseId: String, expiresAt: Date?)
        case expired(licenseId: String)
        /// Suspended or banned on the server.
        case revoked(licenseId: String)
        /// Transport or protocol problem. Retryable, never a verdict.
        case protocolFailure(String)
    }

    private enum TrialLookupResult {
        case notFound(evidence: AuthoritativeEvidence)
        case active(
            licenseId: String,
            expiresAt: Date?,
            evidence: AuthoritativeEvidence
        )
        /// Expired, suspended or banned. The trial can never admit service again.
        case ended(licenseId: String, evidence: AuthoritativeEvidence)
        case networkError(String)
    }

    private struct VerifiedResponse {
        let statusCode: Int
        let body: Data
        let evidence: AuthoritativeEvidence
    }

    private enum LicenseTransportResult {
        case verified(VerifiedResponse)
        case failure(String)
    }

    /// Performs a license request and refuses to look at the body until the
    /// response signature, digest, request target, server date and, where the
    /// endpoint supports it, the validation nonce all verify.
    ///
    /// A nil trusted instant is a positive rollback detection, never missing
    /// information. The rolled-back wall clock is not substituted for it, so the
    /// verifier refuses every response that is not bound to a fresh nonce.
    private func send(
        _ request: URLRequest,
        expectedNonce: Int? = nil
    ) async -> LicenseTransportResult {
        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return .failure("Invalid response")
            }
            switch verifier.verify(
                request: request,
                response: httpResponse,
                body: data,
                expectedNonce: expectedNonce,
                now: trustedNow()
            ) {
            case .success(let evidence):
                if expectedNonce != nil {
                    trustedClock.observe(evidence)
                }
                return .verified(
                    VerifiedResponse(
                        statusCode: httpResponse.statusCode,
                        body: data,
                        evidence: evidence
                    )
                )
            case .failure(let failure):
                AgentLogger.shared.error(
                    "Rejected unverified license response: \(failure.description)"
                )
                return .failure(failure.description)
            }
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    /// Parses a validate-key response.
    ///
    /// Keygen returns real license rejections as `200` + `meta.valid`/`meta.code`,
    /// so any other status is an availability or protocol problem and stays
    /// retryable instead of becoming a durable rejection.
    static func parseKeyValidationVerdict(
        data: Data,
        statusCode: Int,
        now: Date,
        key: String
    ) -> KeyValidationVerdict {
        guard statusCode == 200 else {
            return .protocolFailure("API error: \(statusCode)")
        }
        guard
            let json = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
            let meta = json["meta"] as? [String: Any],
            let valid = meta["valid"] as? Bool
        else {
            return .protocolFailure("Invalid response format")
        }

        let dataObject = json["data"] as? [String: Any]
        let licenseId = dataObject?["id"] as? String
        var expiresAt: Date? = nil
        if let rawAttributes = dataObject?["attributes"] {
            guard let attributes = rawAttributes as? [String: Any] else {
                return .protocolFailure("Invalid response format")
            }
            if let rawExpiry = attributes["expiry"] {
                if rawExpiry is NSNull {
                    expiresAt = nil
                } else {
                    guard
                        let expiry = rawExpiry as? String,
                        let parsedExpiry = Self.parseISO8601Date(expiry)
                    else {
                        return .protocolFailure("Invalid response format")
                    }
                    expiresAt = parsedExpiry
                }
            }
        }
        // Keygen omits the key only for legacy encrypted licenses, so an absent
        // key cannot be held against the answer.
        if let dataObject, let signedKey = signedLicenseKey(in: dataObject), signedKey != key {
            return .protocolFailure("Response describes another license")
        }

        if valid {
            guard let licenseId, !licenseId.isEmpty else {
                return .protocolFailure("Invalid response format")
            }
            return .valid(licenseId: licenseId, expiresAt: expiresAt)
        }

        let code = meta["code"] as? String ?? ""
        if code == "SUSPENDED" {
            return .suspended
        }
        // `NO_MACHINE(S)` means the license has no machines yet, and
        // `FINGERPRINT_SCOPE_MISMATCH` means other machines hold its seats. Both
        // ask for this machine to be activated, the seat limit is enforced there.
        if code == "NO_MACHINE" || code == "NO_MACHINES"
            || code == "FINGERPRINT_SCOPE_MISMATCH"
        {
            guard let licenseId, !licenseId.isEmpty else {
                return .protocolFailure("Invalid response format")
            }
            if let expiresAt, now >= expiresAt {
                return .expired
            }
            return .machineActivationRequired(
                licenseId: licenseId,
                expiresAt: expiresAt
            )
        }
        if code == "EXPIRED" {
            return .expired
        }
        return .invalid
    }

    /// Reads what a stored `validate-key` answer proves. Its signature is
    /// already verified, so `body` is what Keygen answered at `validatedAt`.
    ///
    /// A state with a license key needs an answer that is valid for that key
    /// and scoped to this product and machine. A state without one holds a
    /// trial and needs this machine's live trial.
    static func offlineProof(
        in body: Data,
        validatedAt: Date,
        licenseKey: String?,
        fingerprint: String
    ) -> LicenseOfflineProof? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        else {
            return nil
        }

        guard let licenseKey else {
            guard
                case .active(_, let expiresAt) = parseTrialLookupVerdict(
                    data: body,
                    statusCode: 200,
                    now: validatedAt,
                    fingerprint: fingerprint,
                    policyId: KeygenConfig.trialPolicyId
                )
            else {
                return nil
            }
            return LicenseOfflineProof(validatedAt: validatedAt, expiresAt: expiresAt)
        }

        let scope = (json["meta"] as? [String: Any])?["scope"] as? [String: Any]
        guard
            scope?["product"] as? String == KeygenConfig.productId,
            scope?["fingerprint"] as? String == fingerprint,
            case .valid(_, let expiresAt) = parseKeyValidationVerdict(
                data: body,
                statusCode: 200,
                now: validatedAt,
                key: licenseKey
            )
        else {
            return nil
        }
        return LicenseOfflineProof(validatedAt: validatedAt, expiresAt: expiresAt)
    }

    private func validateKeyWithAPI(key: String) async -> KeyValidationResult {
        guard let fingerprint = await resolvedFingerprint() else {
            return .networkError("Cannot validate: machine identity unavailable")
        }

        var request = URLRequest(url: Self.validateKeyURL)
        request.httpMethod = "POST"
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = LicenseRequestBudget.perRequest

        // A fresh nonce per request. It is echoed inside the signed body, so a
        // replayed older response cannot pass verification.
        let nonce = LicenseResponseVerifier.makeNonce()
        let body: [String: Any] = [
            "meta": [
                "key": key,
                "nonce": nonce,
                "scope": [
                    "fingerprint": fingerprint,
                    "product": KeygenConfig.productId,
                ],
            ]
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            return .networkError("Failed to encode request")
        }

        switch await send(request, expectedNonce: nonce) {
        case .failure(let message):
            return .networkError(message)

        case .verified(let response):
            switch Self.parseKeyValidationVerdict(
                data: response.body,
                statusCode: response.statusCode,
                now: response.evidence.serverTime,
                key: key
            ) {
            case .valid(let licenseId, let expiresAt):
                return .valid(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: response.evidence
                )
            case .machineActivationRequired(let licenseId, let expiresAt):
                return .machineActivationRequired(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: response.evidence
                )
            case .expired:
                return .expired(evidence: response.evidence)
            case .suspended:
                return .suspended(evidence: response.evidence)
            case .invalid:
                return .invalid(evidence: response.evidence)
            case .protocolFailure(let message):
                return .networkError(message)
            }
        }
    }

    private func activateMachineWithAPI(
        licenseKey: String, licenseId: String
    ) async
        -> MachineActivationResult
    {
        guard let fingerprint = await resolvedFingerprint() else {
            return .networkError("Cannot activate: machine identity unavailable")
        }

        let url = URL(string: "\(KeygenConfig.baseURL)/machines")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.setValue("License \(licenseKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = LicenseRequestBudget.perRequest

        let machineName = Host.current().localizedName ?? "Mac"
        let username = NSUserName()
        let hostname = ProcessInfo.processInfo.hostName

        let body: [String: Any] = [
            "data": [
                "type": "machines",
                "attributes": [
                    "fingerprint": fingerprint,
                    "name": machineName,
                    "metadata": [
                        "username": username,
                        "hostname": hostname,
                    ],
                ],
                "relationships": [
                    "license": [
                        "data": [
                            "type": "licenses",
                            "id": licenseId,
                        ]
                    ]
                ],
            ]
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            return .networkError("Failed to encode request")
        }

        let response: VerifiedResponse
        switch await send(request) {
        case .failure(let message):
            return .networkError(message)
        case .verified(let verified):
            response = verified
        }

        switch response.statusCode {
        case 201:
            if let json = try? JSONSerialization.jsonObject(with: response.body)
                as? [String: Any],
                let dataObj = json["data"] as? [String: Any],
                let machineId = dataObj["id"] as? String
            {
                return .success(machineId: machineId, evidence: response.evidence)
            }
            return .networkError("Invalid response format")

        case 409:
            switch await findExistingMachine(
                licenseKey: licenseKey,
                licenseId: licenseId,
                fingerprint: fingerprint
            ) {
            case .found(let machineId, let evidence):
                return .alreadyActivated(machineId: machineId, evidence: evidence)
            case .networkError(let message):
                return .networkError(message)
            case .notFound:
                // The seat is taken but not listed: the answers disagree, so
                // they are no verdict and the activation is tried again.
                return .networkError("Machine already activated but couldn't retrieve ID")
            }

        case 422:
            let errors = KeygenAPIError.errors(in: response.body)
            if errors.contains(code: "FINGERPRINT_TAKEN", pointer: "/data/attributes/fingerprint") {
                switch await findExistingMachine(
                    licenseKey: licenseKey,
                    licenseId: licenseId,
                    fingerprint: fingerprint
                ) {
                case .found(let machineId, let evidence):
                    return .alreadyActivated(machineId: machineId, evidence: evidence)
                case .networkError(let message):
                    return .networkError(message)
                case .notFound:
                    return .networkError("Machine already exists but couldn't retrieve ID")
                }
            }
            if let limitError = errors.first(code: "MACHINE_LIMIT_EXCEEDED") {
                AgentLogger.shared.warning("Machine activation rejected: machine limit reached")
                return .machineLimit(
                    limit: limitError.trailingLimit ?? 2,
                    evidence: response.evidence
                )
            }
            let codes = errors.map { $0.code ?? "unknown" }.joined(separator: ",")
            AgentLogger.shared.warning("Machine activation rejected: \(codes)")
            return .unrecognizedRejection(
                errors.first?.detail ?? "Machine activation was rejected"
            )

        default:
            AgentLogger.shared.error(
                "Machine activation failed with status \(response.statusCode)"
            )
            // Only 409 and 422 carry a semantic activation verdict. Every other
            // status stays retryable instead of being persisted as terminal.
            return .networkError("API error: \(response.statusCode)")
        }
    }

    private func findExistingMachine(
        licenseKey: String,
        licenseId: String,
        fingerprint: String
    ) async -> ExistingMachineLookupResult {
        let encodedFP =
            fingerprint.addingPercentEncoding(
                withAllowedCharacters: .urlQueryAllowed
            ) ?? fingerprint
        let url = URL(
            string: "\(KeygenConfig.baseURL)/machines?fingerprint=\(encodedFP)&license=\(licenseId)"
        )!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.setValue("License \(licenseKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = LicenseRequestBudget.perRequest

        switch await send(request) {
        case .failure(let message):
            AgentLogger.shared.error("Failed to find existing machine: \(message)")
            return .networkError(message)

        case .verified(let response):
            guard response.statusCode == 200 else {
                return .networkError("API error: \(response.statusCode)")
            }
            guard
                let json = try? JSONSerialization.jsonObject(with: response.body)
                    as? [String: Any],
                let dataArray = json["data"] as? [[String: Any]]
            else {
                return .networkError("Invalid response format")
            }
            guard
                let firstMachine = dataArray.first,
                let machineId = firstMachine["id"] as? String,
                !machineId.isEmpty
            else {
                return .notFound
            }
            return .found(machineId: machineId, evidence: response.evidence)
        }
    }

    /// Releases the machine seat.
    ///
    /// Deactivation is rights-reducing, so it does not require response
    /// verification. Refusing to release a seat because a response could not be
    /// verified would only strand the user's own machine.
    private func deactivateMachineWithAPI(licenseKey: String, machineId: String) async -> Bool {
        let url = URL(string: "\(KeygenConfig.baseURL)/machines/\(machineId)")!
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("License \(licenseKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = LicenseRequestBudget.perRequest

        do {
            let (_, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                return false
            }

            return httpResponse.statusCode == 204 || httpResponse.statusCode == 200
                || httpResponse.statusCode == 404
        } catch {
            AgentLogger.shared.error("Failed to deactivate machine: \(error.localizedDescription)")
            return false
        }
    }

    private func registerTrialWithAPI(fingerprint: String) async -> TrialRegistrationResult {
        guard let trialToken else {
            AgentLogger.shared.error("Cannot create a trial: this build has no Keygen trial token")
            return .retryable("no trial token in this build")
        }
        let url = URL(string: "\(KeygenConfig.baseURL)/licenses")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(trialToken)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = LicenseRequestBudget.perRequest

        let username = NSUserName()
        let hostname = ProcessInfo.processInfo.hostName

        let body: [String: Any] = [
            "data": [
                "type": "licenses",
                "attributes": [
                    "key": fingerprint,  // One trial per machine: Keygen rejects a duplicate key.
                    "metadata": [
                        "type": "trial",
                        "username": username,
                        "hostname": hostname,
                    ],
                ],
                "relationships": [
                    "policy": [
                        "data": [
                            "type": "policies",
                            "id": KeygenConfig.trialPolicyId,
                        ]
                    ]
                ],
            ]
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            return .retryable("Failed to encode request")
        }

        let response: VerifiedResponse
        switch await send(request) {
        case .failure(let message):
            return .retryable(message)
        case .verified(let verified):
            response = verified
        }

        switch response.statusCode {
        case 200, 201:
            guard
                let json = try? JSONSerialization.jsonObject(with: response.body)
                    as? [String: Any],
                let dataObj = json["data"] as? [String: Any],
                let licenseId = dataObj["id"] as? String,
                let attributes = dataObj["attributes"] as? [String: Any]
            else {
                AgentLogger.shared.error("Failed to parse trial response JSON")
                return .retryable("Invalid response format")
            }
            guard
                Self.isTrial(dataObj, of: fingerprint, policyId: KeygenConfig.trialPolicyId)
            else {
                AgentLogger.shared.error("Trial response describes another license")
                return .retryable("Response describes another license")
            }
            // A null expiry falls back to the trial duration from signed server time.
            guard let expiry = attributes["expiry"] as? String else {
                let expiresAt = response.evidence.serverTime
                    .addingTimeInterval(Constants.trialDuration)
                AgentLogger.shared.info("No expiry in response, using calculated: \(expiresAt)")
                return .success(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: response.evidence
                )
            }
            guard let expiresAt = Self.parseISO8601Date(expiry) else {
                AgentLogger.shared.error("Failed to parse expiry date: \(expiry)")
                return .retryable("Invalid expiry format")
            }
            return .success(
                licenseId: licenseId,
                expiresAt: expiresAt,
                evidence: response.evidence
            )

        case 422:
            let errors = KeygenAPIError.errors(in: response.body)
            if errors.contains(code: "KEY_TAKEN", pointer: "/data/attributes/key") {
                return .keyTaken
            }
            let codes = errors.map { $0.code ?? "unknown" }.joined(separator: ",")
            AgentLogger.shared.warning("Trial registration rejected: \(codes)")
            return .retryable("Trial registration rejected: \(codes)")

        default:
            return .retryable("API error: \(response.statusCode)")
        }
    }

    /// Parses the trial lookup.
    ///
    /// The trial policy requires machines that onboarding never activates, so a
    /// live trial answers `NO_MACHINES` and `meta.valid` cannot decide. Only
    /// `NOT_FOUND`, `SUSPENDED` and `BANNED` are read from the code, everything
    /// else from the signed expiry. A malformed body or expiry is a protocol
    /// failure, so a garbled response can never disable an active trial.
    static func parseTrialLookupVerdict(
        data: Data,
        statusCode: Int,
        now: Date,
        fingerprint: String,
        policyId: String
    ) -> TrialLookupVerdict {
        guard statusCode == 200 else {
            return .protocolFailure("API error: \(statusCode)")
        }
        guard
            let json = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
            let meta = json["meta"] as? [String: Any]
        else {
            return .protocolFailure("Invalid response format")
        }

        let code = meta["code"] as? String
        if code == "NOT_FOUND" {
            return .notFound
        }
        if code == "POLICY_SCOPE_MISMATCH" {
            return .protocolFailure("Fingerprint key belongs to another policy")
        }
        guard
            let dataObject = json["data"] as? [String: Any],
            let licenseId = dataObject["id"] as? String,
            !licenseId.isEmpty
        else {
            return .protocolFailure("Invalid response format")
        }
        guard isTrial(dataObject, of: fingerprint, policyId: policyId) else {
            return .protocolFailure("Response describes another license")
        }
        if code == "SUSPENDED" || code == "BANNED" {
            return .revoked(licenseId: licenseId)
        }

        let attributes = dataObject["attributes"] as? [String: Any]
        guard let rawExpiry = attributes?["expiry"], !(rawExpiry is NSNull) else {
            return .active(licenseId: licenseId, expiresAt: nil)
        }
        guard
            let expiry = rawExpiry as? String,
            let expiresAt = Self.parseISO8601Date(expiry)
        else {
            return .protocolFailure("Invalid expiry format")
        }
        return now < expiresAt
            ? .active(licenseId: licenseId, expiresAt: expiresAt)
            : .expired(licenseId: licenseId)
    }

    /// Keygen signs its response, not the request body, so a relay that reads
    /// the nonce can ask about another license and pass that signed answer on.
    /// Only the license named inside the signed body proves what was answered.
    static func signedLicenseKey(in dataObject: [String: Any]) -> String? {
        (dataObject["attributes"] as? [String: Any])?["key"] as? String
    }

    static func isTrial(
        _ dataObject: [String: Any],
        of fingerprint: String,
        policyId: String
    ) -> Bool {
        let policy = (dataObject["relationships"] as? [String: Any])?["policy"] as? [String: Any]
        let signedPolicyId = (policy?["data"] as? [String: Any])?["id"] as? String
        return signedLicenseKey(in: dataObject) == fingerprint && signedPolicyId == policyId
    }

    /// Looks up this machine's trial by its fingerprint key.
    ///
    /// The request is public and bound to a fresh nonce, so its answer is
    /// authoritative even when the local clock is wrong. Every lookup is also the
    /// trial's usage callhome.
    private func lookupTrialWithAPI() async -> TrialLookupResult {
        guard let fingerprint = await resolvedFingerprint() else {
            return .networkError("Machine identity unavailable")
        }
        var request = URLRequest(url: Self.validateKeyURL)
        request.httpMethod = "POST"
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = LicenseRequestBudget.perRequest
        let nonce = LicenseResponseVerifier.makeNonce()
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: [
                "meta": [
                    "key": fingerprint,
                    "nonce": nonce,
                    "scope": ["policy": KeygenConfig.trialPolicyId],
                ]
            ])
        } catch {
            return .networkError("Failed to encode request")
        }

        switch await send(request, expectedNonce: nonce) {
        case .failure(let message):
            return .networkError(message)
        case .verified(let response):
            switch Self.parseTrialLookupVerdict(
                data: response.body,
                statusCode: response.statusCode,
                now: response.evidence.serverTime,
                fingerprint: fingerprint,
                policyId: KeygenConfig.trialPolicyId
            ) {
            case .notFound:
                return .notFound(evidence: response.evidence)
            case .active(let licenseId, let expiresAt):
                return .active(
                    licenseId: licenseId,
                    expiresAt: expiresAt,
                    evidence: response.evidence
                )
            case .expired(let licenseId), .revoked(let licenseId):
                return .ended(licenseId: licenseId, evidence: response.evidence)
            case .protocolFailure(let message):
                return .networkError(message)
            }
        }
    }
}
