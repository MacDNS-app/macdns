// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Combine
import Foundation
@preconcurrency import NetworkExtension
import ServiceManagement
import Shared
import SwiftUI
import SystemExtensions
@preconcurrency import UserNotifications

struct LicenseExpirationNotificationPlan {
    struct Notification: Equatable {
        let id: String
        let title: String
        let body: String
        let timeInterval: TimeInterval
    }

    let identifiersToRemove: [String]
    let notifications: [Notification]

    private static let thresholds: [(suffix: String, hoursBefore: Int, message: String)] = [
        ("24h", 24, "expires in 24 hours"),
        ("12h", 12, "expires in 12 hours"),
        ("2h", 2, "expires in 2 hours"),
        ("now", 0, "has expired"),
    ]

    static func make(
        for info: LicenseInfo?,
        now: Date = Date()
    ) -> LicenseExpirationNotificationPlan {
        let identifiersToRemove = ["trial", "license"].flatMap { prefix in
            thresholds.map { "\(prefix)-expiring-\($0.suffix)" }
        }
        guard let info, let expiresAt = info.expiresAt else {
            return LicenseExpirationNotificationPlan(
                identifiersToRemove: identifiersToRemove,
                notifications: []
            )
        }

        let isTrial = info.status == .trial
        let prefix = isTrial ? "trial" : "license"
        let typeLabel = isTrial ? "trial" : "license"
        let notifications = thresholds.compactMap { threshold -> Notification? in
            let fireDate = expiresAt.addingTimeInterval(
                -Double(threshold.hoursBefore) * 3600
            )
            let timeInterval = fireDate.timeIntervalSince(now)
            guard timeInterval > 1 else { return nil }

            let isExpired = threshold.hoursBefore == 0
            let title =
                isTrial
                ? (isExpired ? "Trial Expired" : "Trial Expiring Soon")
                : (isExpired ? "License Expired" : "License Expiring Soon")
            let actionMessage =
                isTrial
                ? "Get a license to continue using MacDNS."
                : "Renew your subscription to continue using MacDNS."
            let body =
                isExpired
                ? "Your \(typeLabel) has expired. \(actionMessage)"
                : "Your \(typeLabel) \(threshold.message). \(actionMessage)"
            return Notification(
                id: "\(prefix)-expiring-\(threshold.suffix)",
                title: title,
                body: body,
                timeInterval: timeInterval
            )
        }

        return LicenseExpirationNotificationPlan(
            identifiersToRemove: identifiersToRemove,
            notifications: notifications
        )
    }
}

enum AgentUpgradeRecoveryAction: Equatable {
    case none
    case resetConnection
    case replaceAgent
}

struct AgentUpgradeRecoveryPolicy {
    static let replacementMinimumSeconds: TimeInterval = 30

    let reason: PersistedStateUnavailableReason
    let elapsed: TimeInterval
    let agentRegistered: Bool
    let authoritativeStartupCompleted: Bool
    let didResetConnection: Bool
    let didAttemptReplacement: Bool

    /// Only a load the Agent never answered points at the connection or the
    /// Agent. One that answered it could not read `state.json` is retried.
    var action: AgentUpgradeRecoveryAction {
        guard reason != .stateReadFailure,
            !authoritativeStartupCompleted, !didAttemptReplacement
        else {
            return .none
        }
        guard didResetConnection else { return .resetConnection }
        guard agentRegistered,
            elapsed >= Self.replacementMinimumSeconds
        else { return .none }
        return .replaceAgent
    }
}

private enum AgentUpdateTrigger: String {
    case binaryMismatch
    case unreachableState
}

@MainActor
class AppViewModel: ObservableObject {
    private let logger = AppLogger.shared.viewModel

    // MARK: - Services
    private let agentInstaller = AgentInstaller.shared
    private let extensionManager = ExtensionManager.shared
    private let filterManager = FilterManager.shared
    private let appLoginItem = SMAppService.mainApp

    // MARK: - Agent & Extension State
    @Published var agentInstalled: Bool = false
    @Published var agentResponding: Bool = false
    @Published var servicesRunning: Bool = false  // True if the resolver is actually running
    @Published var extensionActive: Bool = false
    @Published var needsPermissionApproval: Bool = false
    @Published private(set) var persistedStateAvailability: PersistedStateAvailability = .loading
    @Published private(set) var firstRunPreparing = false
    @Published private(set) var firstRunTrialEnded = false
    /// True once the trial step finished in this launch.
    @Published private(set) var firstRunTrialStepFinished = false
    /// Notification authorization is no longer `.notDetermined`.
    @Published private(set) var notificationsDecided = false
    @Published private(set) var firstRunNotificationsSkipped = false
    /// The step whose Continue gate is open, nil otherwise and while macOS
    /// shows the step's request.
    @Published private(set) var firstRunAwaitingContinue: FirstRunSetupStep?
    /// Set by the first-run window controller to the step the click that
    /// starts setup answers, so its gate does not wait.
    var firstRunApprovedStep: FirstRunSetupStep?
    @Published private(set) var freshInstallSetupRunning = false
    /// How the last fresh install setup attempt ended, nil while one runs.
    @Published private(set) var freshInstallSetupOutcome: FreshInstallSetupOutcome?
    /// The status message from when the setup attempt failed, as in the failure alert.
    @Published private(set) var freshInstallSetupFailureMessage: String?
    /// Set by the first-run window controller. While open, the window shows
    /// the setup outcome instead of an alert.
    var firstRunWindowOpen = false {
        didSet { updateLateProviderRegistrationDeferral() }
    }
    private var firstRunNotificationWait: FirstRunNotificationWait?
    private var firstRunContinueGate: FirstRunContinueGate?
    /// Set while "Quit and Remove Services" runs, so the first-run trial step
    /// never registers the Agent it is removing.
    private(set) var servicesRemovalRequested = false
    /// Set by Uninstall for the rest of the process. The first-run window can
    /// stay open through it before setup starts, and its exit must not
    /// register the Agent again.
    private(set) var servicesRemoved = false

    var isInitialStateLoading: Bool {
        persistedStateAvailability != .loaded
    }

    private var cancellables = Set<AnyCancellable>()
    @Published private(set) var agentNeedsPermissionApproval: Bool = false
    private var extensionNotice: ExtensionNotice = .none
    private var contentFilterEnableTask: Task<Void, Never>?
    private var agentInstallTask: Task<Void, Error>?
    private let agentInstallSerializer = AgentInstallSerializer()
    /// The fresh install in flight, or a restart or restore of the registration.
    private var runningAgentInstall: Task<Void, Error>? {
        agentInstallTask ?? agentInstallSerializer.running
    }
    private var contentFilterEnableGeneration = 0
    @Published private(set) var isEnablingDNS = false
    private var isStoppingDNS = false
    @Published private(set) var softwareUpdateSuspended = false
    private var agentWasRegisteredBeforeSoftwareUpdate = false
    private var runtimeWasDesiredBeforeSoftwareUpdate = false
    private var isStoppingUnexpectedResolver = false
    private var resumeDNSAfterProxyApproval = false
    /// A change supersedes the running attempt. Ending the first-run waits
    /// lets an attempt suspended on one see it and stop.
    private var dnsLifecycleGeneration: UInt64 = 0 {
        didSet {
            endFirstRunWaits()
            updateLateProviderRegistrationDeferral()
        }
    }
    private var runtimeDNSDesired = false
    private var persistedStateMutationGeneration: UInt64 = 0
    private var persistedStateLoadGeneration: UInt64 = 0
    private var postRecoveryReconciliation =
        PersistedStatePostRecoveryReconciliation()
    /// The DNS lifecycle generation the fresh install setup belongs to, nil
    /// when no setup is in progress.
    private var freshInstallSetupGeneration: UInt64? {
        didSet {
            freshInstallSetupRunning = freshInstallSetupGeneration != nil
            updateLateProviderRegistrationDeferral()
        }
    }
    private var isApplyingPersistedState = false
    private var isAutoStartingServices = false
    private var serviceWakeReconciliationTask: Task<Void, Never>?
    private var serviceWakeReconciliationPending = false
    private var runtimeStateRefreshRetryTask: Task<Void, Never>?
    private var runtimeStateRefreshRetryPolicy = RuntimeStateRefreshRetryPolicy()
    private var runtimeStateRefreshRetryGeneration: UInt64 = 0
    private var serviceWakeGeneration: UInt64 = 0
    private var licenseStatusWakeTask: Task<Void, Never>?
    private var licenseStatusWakePending = false
    private var licenseStatusWakeGeneration: UInt64 = 0
    private var startupAuxiliaryLoadsStarted = false
    private var didCompleteAuthoritativeStartup = false
    private var authoritativeStateRecoveryStartedAt: TimeInterval?
    private var didLogAuthoritativeStateUnavailable = false
    private var didResetConnectionForUnreachableAgent = false
    private var didAttemptAgentReplacementForUnreachableState = false
    private var agentReplacementInProgress = false

    private nonisolated let serviceWakeupGate = ServiceWakeupGate()
    private nonisolated let licenseStatusWakeupGate = ServiceWakeupGate()
    private lazy var fullConfigSaveCoordinator = FullConfigSaveCoordinator(
        revision: 0,
        saveToAgent: { config in
            await XPCClient.shared.saveFullConfigAsync(config: config)
        },
        loadAuthoritative: { [weak self] in
            switch await XPCClient.shared.getFullConfigAsync() {
            case .success(let config):
                return config
            case .failure(.agentNotResponding),
                .failure(.connectionInterrupted):
                guard
                    let self,
                    self.agentInstaller.canUseStateFileFallback()
                else {
                    return nil
                }
                return self.loadStateFromFile()
            case .failure:
                return nil
            }
        },
        shouldUseFallback: { [weak self] in
            guard let self else { return false }
            return self.agentInstaller.canUseStateFileFallback()
        },
        saveFallback: { [weak self] snapshot, expectedRevision in
            guard
                let self,
                self.agentInstaller.canUseStateFileFallback()
            else {
                self?.logger.warning(
                    "Fallback state save skipped because the agent service can still execute"
                )
                return nil
            }
            return self.saveStateToFile(
                snapshot,
                expectedRevision: expectedRevision
            )
        },
        applyAuthoritative: { [weak self] config in
            _ = self?.applyPersistedConfig(config)
        },
        publishOutcome: { [weak self] outcome in
            self?.handleConfigSaveOutcome(outcome)
        }
    )
    private lazy var persistedStateRecoveryCoordinator =
        PersistedStateRecoveryCoordinator(
            loadAttempt: { [weak self] attempt in
                guard let self else { return .superseded }
                let loadGeneration = self.persistedStateLoadGeneration
                return await self.performPersistedStateLoadAttempt(
                    attempt: attempt,
                    expectedLoadGeneration: loadGeneration
                )
            },
            attemptCompletion: { [weak self] outcome, attempt in
                self?.handlePersistedStateLoadCompletion(
                    outcome,
                    attempt: attempt
                )
            }
        )

    var protectionDisplayState: ProtectionDisplayState {
        ProtectionDisplayState(
            isEnabled: isEnabled,
            servicesRunning: servicesRunning,
            dnsProxyEnabled: extensionManager.proxyEnabled,
            providerState: providerState,
            forwarding: providerForwarding,
            captivePortalDetected: captivePortalDetected
        )
    }

    var isProtectionActive: Bool {
        protectionDisplayState.isProtectionActive
    }

    var showsPermissionApprovalBanner: Bool {
        permissionApprovalMessage != nil
    }

    var permissionApprovalMessage: String? {
        extensionNotice.permissionBannerMessage(
            isProtectionActive: protectionDisplayState.isProtectionActive,
            fallbackNeedsApproval: needsPermissionApproval
        )
    }

    private var anyExtensionNeedsUserApproval: Bool {
        extensionManager.needsUserApproval || filterManager.needsUserApproval
    }

    private func refreshPermissionApprovalState(proxyNeedsApproval: Bool? = nil, filterNeedsApproval: Bool? = nil) {
        needsPermissionApproval =
            PermissionApprovalStatePolicy(
                agentNeedsApproval: agentNeedsPermissionApproval,
                proxyNeedsApproval: proxyNeedsApproval ?? extensionManager.needsUserApproval,
                filterNeedsApproval: filterNeedsApproval ?? filterManager.needsUserApproval
            )
            .needsPermissionApproval
    }

    private func setAgentPermissionApprovalRequired(_ needsApproval: Bool) {
        agentNeedsPermissionApproval = needsApproval
        refreshPermissionApprovalState()
    }

    /// Derived only from the agent's runtime flags: `captivePortalDetected`
    /// means an approved full bypass is active, `providerForwarding` means the
    /// constrained captive compatibility mode is active.
    private var captiveCompatibilityMode: CaptivePortalCompatibilityMode {
        CaptivePortalCompatibilityMode.from(
            fullBypassActive: captivePortalDetected,
            forwarding: providerForwarding
        )
    }

    /// True while the agent runs the constrained compatibility mode: protection
    /// is still on and only a deliberate user action may widen it to a full
    /// bypass for the attached network.
    var showsCaptiveBypassApproval: Bool {
        agentInstalled && captiveCompatibilityMode == .scopedForwarding
    }

    private var shouldKeepContentFilterEnabled: Bool {
        runtimeDNSDesired && !isStoppingDNS && !softwareUpdateSuspended
            && ContentFilterActivationPolicy(
                blockDohDotEnabled: blockDohDotEnabled,
                isEnabled: isEnabled,
                servicesRunning: servicesRunning,
                dnsProxyEnabled: extensionManager.proxyEnabled,
                captiveMode: captiveCompatibilityMode,
                licenseValid: isLicenseValid,
                filterEnabled: filterManager.filterEnabled
            ).shouldKeepEnabled
    }

    private var shouldDisableContentFilter: Bool {
        filterManager.filterEnabled && !shouldKeepContentFilterEnabled
    }

    private var shouldEnableContentFilter: Bool {
        !filterManager.filterEnabled && shouldKeepContentFilterEnabled
    }

    // MARK: - Persisted State (Daemon is the Single Source of Truth)
    @Published var isEnabled: Bool = false {
        didSet {
            guard oldValue != isEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var dnssecEnabled: Bool = true {
        didSet {
            guard oldValue != dnssecEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var logQueriesEnabled: Bool = false {
        didSet {
            guard oldValue != logQueriesEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var logRepliesEnabled: Bool = false {
        didSet {
            guard oldValue != logRepliesEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var prefetchEnabled: Bool = true {
        didSet {
            guard oldValue != prefetchEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var serveExpiredEnabled: Bool = true {
        didSet {
            guard oldValue != serveExpiredEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    /// The four lookup-history keys, kept together so a retention change that
    /// also shortens the look-back is one save.
    @Published var queryHistorySettings: QueryHistorySettings = .default {
        didSet {
            guard oldValue != queryHistorySettings else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var dohProviders: Set<DoHProviderID> = Set(DoHProviderID.defaultProviders) {
        didSet {
            guard oldValue != dohProviders else { return }
            if dohProviders.isEmpty {
                dohProviders = oldValue.isEmpty ? Set(DoHProviderID.defaultProviders) : oldValue
                return
            }
            saveFullConfigToDaemon()
        }
    }

    @Published var dohDispatchMode: DoHDispatchMode = .defaultMode {
        didSet {
            guard oldValue != dohDispatchMode else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var dnsAnswerRefinementEnabled: Bool = true {
        didSet {
            guard oldValue != dnsAnswerRefinementEnabled else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var blockDohDotEnabled: Bool = false {
        didSet {
            let sideEffect = PersistedStateSideEffectPolicy.blockDohDotSideEffect(
                oldValue: oldValue,
                newValue: blockDohDotEnabled,
                isApplyingPersistedState: isApplyingPersistedState
            )
            guard sideEffect != .none else { return }
            saveFullConfigToDaemon()
            Task { @MainActor in
                await applyBlockDohDotSideEffect(sideEffect)
            }
        }
    }

    // MARK: - Captive Portal State (Read-only)
    @Published var resolverMode: String = ProtectionStatusPolicy.encryptedModeMessage
    @Published var captivePortalDetected: Bool = false
    // Authenticated interception state from the Agent's runtime snapshot only.
    @Published private(set) var providerState: ProviderInterceptionDisplayState = .unknown
    // True when the provider intercepts through plaintext forwarding (degraded).
    @Published private var providerForwarding: Bool = false
    // True when the live provider runs an older build than the bundled extension
    // (update lands on restart). Drives the restart-required notice.
    @Published private var extensionVersionStale: Bool = false
    /// Layer-3 signal: proxy-control bounces were exhausted without recovery,
    /// and only a restart can resubmit the provider job. Drives .restartRequired.
    @Published private(set) var proxyControlRecoveryExhausted = false
    private var proxyControlBounceTask: Task<Void, Never>?
    private var proxyControlBounceInProgress = false
    private var proxyControlBounceAttempts = 0
    private var proxyControlLastBounceAt: Date?

    @Published var customZones: [ForwardZone] = [] {
        didSet {
            guard oldValue != customZones else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var dnsOverrides: [DNSOverride] = [] {
        didSet {
            guard oldValue != dnsOverrides else { return }
            saveFullConfigToDaemon()
        }
    }

    @Published var statusMessage: String = "Ready"
    @Published private(set) var cleanupRequiresRestart = false

    /// Last configuration-save failure, shown until a later save succeeds.
    @Published private(set) var configSaveFailureMessage: String?

    // MARK: - Blocklist State
    @Published var blocklistEnabled: Bool = false {
        didSet {
            guard !isLoadingBlocklist else { return }
            saveBlocklistSettings()
        }
    }

    /// Blocklist settings persist inside `state.json` and travel over their own
    /// XPC calls. Mutation stays blocked until this subsystem's own load
    /// succeeds, so defaults never overwrite the user's saved categories.
    @Published private(set) var blocklistSettingsLoaded: Bool = false

    // Internal storage for blocklist settings (in Rust format)
    private var blocklistSettings: BlocklistSettings = BlocklistSettings()
    private var blocklistSettingsLoadGeneration: UInt64 = 0

    // Bumped on every change to the unpublished blocklistSettings, so views refresh.
    @Published var blocklistSettingsVersion: Int = 0
    @Published var isUpdatingBlocklist: Bool = false

    // MARK: - Blocklist Statistics
    @Published var blocklistStats: [BlockedDomain] = []
    @Published var isLoadingStats: Bool = false
    /// Set when the history could not give Activity its list.
    @Published private(set) var blocklistStatsIssue: QueryHistoryLoad<[BlockedDomain]>?
    @Published var activityRange: QueryHistoryRange = .day
    private var activityStatsRefresh = ActivityStatsRefreshState()

    // MARK: - Lookup History
    @Published private(set) var queryHistoryClear = QueryHistoryClearState()
    @Published private(set) var queryHistoryStatus: QueryHistoryLoad<QueryHistoryStatus>?
    /// Kept for the app run only, never saved.
    @Published var queriesRefreshInterval = QueriesAutoRefresh.defaultInterval

    // MARK: - Allowlist State
    @Published var allowedDomains: [AllowedDomain] = []

    // MARK: - Agent Update State
    @Published private(set) var isUpdatingAgent: Bool = false

    // MARK: - License State
    @Published var licenseInfo: LicenseInfo? {
        didSet {
            if oldValue?.expiresAt != licenseInfo?.expiresAt
                || oldValue?.status != licenseInfo?.status
            {
                scheduleExpirationNotifications()
            }
        }
    }

    var isLicenseValid: Bool {
        licenseInfo?.isServiceAllowed ?? true
    }
    @Published var isLoadingLicense: Bool = false
    @Published var licenseActivationFeedback: LicenseActivationFeedback?

    // MARK: - Update State
    @Published var updateInfo: UpdateInfo?

    private lazy var updateInfoLoader = UpdateInfoLoader(
        load: { await XPCClient.shared.getUpdateInfo() },
        didLoad: { [weak self] in self?.updateInfo = $0 },
        present: { await UpdaterManager.shared.showUpdateIfAvailable($0) }
    )

    private var isLoading: Bool = false
    private var isLoadingBlocklist: Bool = false
    private var isLoadingAllowlist: Bool = false
    private var isServiceStatusCheckInFlight: Bool = false
    private var serviceStatusCheckCompletedAt: TimeInterval?
    private let serviceStatusCheckGate = ServiceStatusCheckGatePolicy.default

    func toggleDoHProvider(_ provider: DoHProviderID) {
        var next = dohProviders
        if next.contains(provider) {
            guard next.count > 1 else { return }
            next.remove(provider)
        } else {
            next.insert(provider)
        }
        dohProviders = next
    }

    var dohProviderSummary: String {
        let selected = DoHProviderID.allCases.filter { dohProviders.contains($0) }
        if selected.count == DoHProviderID.allCases.count { return "All" }
        if selected.count == 1 { return selected[0].displayName }
        return "\(selected.count) Selected"
    }

    private var embeddedAgentPath: String {
        Bundle.main.bundlePath + "/Contents/MacOS/MacDNSAgent"
    }

    // MARK: - Initialization
    init() {
        logger.info("AppViewModel initializing")

        // Set first so didSet observers stay quiet during init.
        isLoading = true

        // These observers do not depend on loaded state.
        observeExtensionStatus()
        observeServicesStatusChanges()
        observeCaptivePortalNotifications()
        observeApplicationActivation()
        UpdaterManager.shared.onUpdateCycleFinished = { [weak self] in
            self?.updateInfoLoader.retryPendingPresentation()
        }
        UpdaterManager.shared.installationLifecycle = SoftwareUpdateLifecycle(
            stop: { [weak self] step in
                await self?.performSoftwareUpdateStop(step) ?? false
            },
            restore: { [weak self] in
                await self?.restoreAfterCancelledSoftwareUpdate()
            }
        )

        Task { @MainActor [weak self] in
            guard let self else { return }
            startupAuxiliaryLoadsStarted = true
            persistedStateRecoveryCoordinator.start()
            loadBlocklistSettings()
            loadLicenseInfo()
            loadUpdateInfo(presentIfAvailable: true)
            completeAuthoritativeStartupIfPossible()
        }
    }

    isolated deinit {
        persistedStateRecoveryCoordinator.cancel()
        updateInfoLoader.cancel()
        runtimeStateRefreshRetryTask?.cancel()

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()

        CFNotificationCenterRemoveObserver(center, observer, CFNotificationName(DarwinNotifications.proxyEnable), nil)
        CFNotificationCenterRemoveObserver(center, observer, CFNotificationName(DarwinNotifications.proxyDisable), nil)
        CFNotificationCenterRemoveObserver(
            center, observer, CFNotificationName(DarwinNotifications.proxyInterceptionChanged), nil)
        CFNotificationCenterRemoveObserver(
            center, observer, CFNotificationName(DarwinNotifications.captivePortalDetected), nil)
        CFNotificationCenterRemoveObserver(
            center, observer, CFNotificationName(DarwinNotifications.captivePortalResolved), nil)
        CFNotificationCenterRemoveObserver(
            center, observer, CFNotificationName(DarwinNotifications.licenseStatusChanged), nil)
        CFNotificationCenterRemoveObserver(
            center, observer, CFNotificationName(DarwinNotifications.updateAvailable), nil)
    }

    private func observeExtensionStatus() {
        extensionManager.$proxyEnabled
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.extensionActive = self?.extensionManager.isActive ?? false
                self?.updateStatusMessage()
            }
            .store(in: &cancellables)

        extensionManager.$isActive
            .receive(on: DispatchQueue.main)
            .sink { [weak self] isActive in
                self?.extensionActive = isActive
                self?.updateStatusMessage()
            }
            .store(in: &cancellables)

        extensionManager.$needsUserApproval
            .combineLatest(filterManager.$needsUserApproval)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] proxyNeedsApproval, filterNeedsApproval in
                guard let self = self else { return }
                self.refreshPermissionApprovalState(
                    proxyNeedsApproval: proxyNeedsApproval,
                    filterNeedsApproval: filterNeedsApproval
                )
                self.extensionNotice.applyApprovalStatus(
                    proxyNeedsApproval: proxyNeedsApproval,
                    filterNeedsApproval: filterNeedsApproval
                )
                self.updateStatusMessage()

                let recoveryPolicy = ContentFilterApprovalRecoveryPolicy(
                    proxyNeedsApproval: proxyNeedsApproval,
                    filterNeedsApproval: filterNeedsApproval,
                    shouldEnableContentFilter: self.shouldEnableContentFilter,
                    restartRequired: self.extensionNotice == .restartRequired
                        || self.extensionManager.activationRequiresRestart
                        || self.filterManager.activationRequiresRestart
                )
                if recoveryPolicy.shouldRetryContentFilterEnable {
                    self.enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                }

                let dnsRecoveryPolicy = DNSProxyApprovalRecoveryPolicy(
                    resumeRequested: self.resumeDNSAfterProxyApproval,
                    proxyNeedsApproval: proxyNeedsApproval,
                    restartRequired: self.extensionManager.activationRequiresRestart,
                    runtimeDNSDesired: self.runtimeDNSDesired,
                    protectionActive: self.protectionDisplayState.isProtectionActive,
                    isEnablingDNS: self.isEnablingDNS,
                    isStoppingDNS: self.isStoppingDNS
                )
                if dnsRecoveryPolicy.shouldResumeDNS {
                    self.resumeDNSAfterProxyApproval = false
                    self.enableDNS()
                }
            }
            .store(in: &cancellables)

        // A replacement drain disables the Content Filter together with the
        // proxy. Its own outcome is the only deterministic trigger that brings
        // the filter back. A Darwin wake-up may never arrive.
        extensionManager.$lastReplacementDrainOutcome
            .compactMap { $0 }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] outcome in
                guard let self = self else { return }
                let policy = ReplacementDrainReconciliationPolicy(outcome: outcome)
                guard policy.shouldScheduleReconciliation else { return }
                self.scheduleServiceStateReconciliation(reason: policy.reason)
            }
            .store(in: &cancellables)

        let restartFromRecovery =
            $proxyControlRecoveryExhausted
            .combineLatest(extensionManager.$replacementDrainUnconfirmed)
            .map { $0 || $1 }

        extensionManager.$activationRequiresRestart
            .combineLatest(
                filterManager.$activationRequiresRestart, $extensionVersionStale,
                restartFromRecovery
            )
            .receive(on: DispatchQueue.main)
            .sink { [weak self] proxyRequiresRestart, filterRequiresRestart, versionStale, recoveryExhausted in
                guard let self = self else { return }
                if proxyRequiresRestart || filterRequiresRestart || versionStale
                    || recoveryExhausted
                {
                    self.setExtensionNotice(.restartRequired)
                } else {
                    self.extensionNotice.clearRestartRequiredIfResolved(
                        proxyRequiresRestart: proxyRequiresRestart,
                        filterRequiresRestart: filterRequiresRestart,
                        versionStale: versionStale,
                        recoveryExhausted: recoveryExhausted
                    )
                    self.updateStatusMessage()
                }
            }
            .store(in: &cancellables)
    }

    private func observeApplicationActivation() {
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                if persistedStateAvailability != .loaded {
                    requestPersistedStateRecoveryIfNeeded()
                }
                refreshApprovalStateAfterExternalChange()
                updateInfoLoader.retryPendingPresentation()
                checkServicesStatus()
            }
            .store(in: &cancellables)
    }

    private func refreshApprovalStateAfterExternalChange() {
        guard agentNeedsPermissionApproval || needsPermissionApproval else { return }

        let agentWasPending = agentNeedsPermissionApproval
        let agentRequiresApproval = agentInstaller.requiresApproval()
        setAgentPermissionApprovalRequired(agentRequiresApproval)
        extensionNotice.applyApprovalStatus(
            proxyNeedsApproval: extensionManager.needsUserApproval,
            filterNeedsApproval: filterManager.needsUserApproval
        )
        updateStatusMessage()

        guard agentWasPending && !agentRequiresApproval else { return }
        if FreshInstallSetupPolicy.resumesEnableAfterAgentApproval(
            agentSetupRequired: persistedStateAvailability == .agentSetupRequired,
            setupGeneration: freshInstallSetupGeneration,
            currentGeneration: dnsLifecycleGeneration,
            runtimeDNSDesired: runtimeDNSDesired,
            isEnablingDNS: isEnablingDNS,
            isStoppingDNS: isStoppingDNS
        ) {
            enableDNS()
        } else {
            checkAgentAndExtensionStatus()
        }
    }

    private func observeServicesStatusChanges() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()

        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.proxyEnable,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.proxyDisable,
            nil,
            .deliverImmediately
        )

        // Register for provider interception-state changes so the UI reflects
        // real interception once the control challenge validates (bypass off).
        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.proxyInterceptionChanged,
            nil,
            .deliverImmediately
        )

        // Persistent proxy-control outage reported by the Agent. Wake-up hint
        // only, because recovery decisions read the authenticated runtime snapshot.
        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.proxyControlOutageChanged,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalLicenseStatusWakeup()
            },
            DarwinNotifications.licenseStatusChanged,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                DispatchQueue.main.async {
                    viewModel.handleUpdateAvailable()
                }
            },
            DarwinNotifications.updateAvailable,
            nil,
            .deliverImmediately
        )
    }

    /// Front-door coalescing for unauthenticated Darwin wake-ups.
    ///
    /// Called directly from the notification callback. The decision to hop to
    /// the main actor is made synchronously under a lock, so a notification
    /// flood cannot build an unbounded main-queue backlog.
    nonisolated func signalServiceWakeup() {
        guard serviceWakeupGate.begin() else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let wakeGeneration = serviceWakeupGate.complete()
            scheduleServiceStateReconciliation(
                reason: "proxy-wakeup",
                wakeGeneration: wakeGeneration
            )
        }
    }

    private func scheduleServiceStateReconciliation(
        reason: String,
        wakeGeneration: UInt64? = nil,
        resetRefreshRetries: Bool = true
    ) {
        guard !isStoppingDNS, !softwareUpdateSuspended else { return }
        guard persistedStateAvailability.allowsLifecycleActions else {
            requestPersistedStateRecoveryIfNeeded()
            updateStatusMessage()
            return
        }

        if resetRefreshRetries { resetRuntimeStateRefreshRetries() }
        serviceWakeGeneration = wakeGeneration ?? serviceWakeupGate.advanceGeneration()
        serviceWakeReconciliationPending = true
        logger.debug("Service state reconciliation requested: \(reason, privacy: .public)")
        guard serviceWakeReconciliationTask == nil else { return }

        serviceWakeReconciliationTask = Task { @MainActor [weak self] in
            guard let self else { return }
            defer { serviceWakeReconciliationTask = nil }

            let transitionRetry = ServiceTransitionRetryPolicy.default
            var transitionRetryCount = 0
            var transitionElapsedNanoseconds: UInt64 = 0

            while serviceWakeReconciliationPending && !Task.isCancelled
                && !isStoppingDNS && !softwareUpdateSuspended
            {
                serviceWakeReconciliationPending = false
                let capturedWakeGeneration = serviceWakeGeneration
                let capturedLifecycleGeneration = dnsLifecycleGeneration
                let result = await XPCClient.shared.getRuntimeStateAsync()
                let generationPolicy = serviceWakeGenerationPolicy(
                    capturedWakeGeneration: capturedWakeGeneration,
                    capturedLifecycleGeneration: capturedLifecycleGeneration
                )
                guard !Task.isCancelled, !isStoppingDNS, !softwareUpdateSuspended else { return }

                switch result {
                case .success(let runtimeState):
                    guard
                        let responding = generationPolicy.agentRespondingUpdate(
                            forXPCSucceeded: true
                        )
                    else { continue }
                    agentResponding = responding

                    if runtimeState.transitionInProgress {
                        switch transitionRetry.decision(
                            retryCount: transitionRetryCount,
                            elapsedNanoseconds: transitionElapsedNanoseconds
                        ) {
                        case .retry(let delayNanoseconds):
                            transitionRetryCount += 1
                            transitionElapsedNanoseconds += delayNanoseconds
                            serviceWakeReconciliationPending = true
                            do {
                                try await Task.sleep(nanoseconds: delayNanoseconds)
                            } catch {
                                return
                            }
                        case .exhausted:
                            logger.warning(
                                "Agent still transitioning after the retry budget; deferring reconciliation"
                            )
                            transitionRetryCount = 0
                            transitionElapsedNanoseconds = 0
                            applyRuntimeStatePresentation(
                                RuntimeStatePresentationPolicy.transitioning
                            )
                            updateStatusMessage()
                            scheduleRuntimeStateRefreshRetry(
                                for: runtimeState,
                                capturedWakeGeneration: capturedWakeGeneration,
                                capturedLifecycleGeneration: capturedLifecycleGeneration
                            )
                        }
                        continue
                    }

                    transitionRetryCount = 0
                    transitionElapsedNanoseconds = 0
                    servicesRunning = runtimeState.servicesRunning
                    captivePortalDetected = runtimeState.captivePortalDetected
                    applyRuntimeStatePresentation(
                        RuntimeStatePresentationPolicy.presentation(for: runtimeState)
                    )
                    scheduleRuntimeStateRefreshRetry(
                        for: runtimeState,
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration
                    )
                    updateStatusMessage()

                    let authoritativeProxyEnabled: Bool
                    do {
                        authoritativeProxyEnabled = try await extensionManager.refreshProxyStatus()
                    } catch {
                        guard
                            isCurrentServiceStateRefresh(
                                capturedWakeGeneration: capturedWakeGeneration,
                                capturedLifecycleGeneration: capturedLifecycleGeneration
                            )
                        else { continue }
                        logger.warning(
                            "Failed to refresh DNS Proxy status: \(error.localizedDescription, privacy: .public)"
                        )
                        updateStatusMessage()
                        continue
                    }

                    guard
                        isCurrentServiceStateRefresh(
                            capturedWakeGeneration: capturedWakeGeneration,
                            capturedLifecycleGeneration: capturedLifecycleGeneration
                        )
                    else { continue }

                    let authoritativeFilterEnabled: Bool
                    do {
                        authoritativeFilterEnabled = try await filterManager.refreshStatus()
                    } catch {
                        guard
                            isCurrentServiceStateRefresh(
                                capturedWakeGeneration: capturedWakeGeneration,
                                capturedLifecycleGeneration: capturedLifecycleGeneration
                            )
                        else { continue }
                        logger.warning(
                            "Failed to refresh Content Filter status: \(error.localizedDescription, privacy: .public)"
                        )
                        updateStatusMessage()
                        continue
                    }

                    guard
                        isCurrentServiceStateRefresh(
                            capturedWakeGeneration: capturedWakeGeneration,
                            capturedLifecycleGeneration: capturedLifecycleGeneration
                        )
                    else { continue }

                    await reconcileServiceRuntimeState(
                        runtimeState,
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration,
                        authoritativeProxyEnabled: authoritativeProxyEnabled,
                        authoritativeFilterEnabled: authoritativeFilterEnabled
                    )
                case .failure(let error):
                    guard
                        let responding = generationPolicy.agentRespondingUpdate(
                            forXPCSucceeded: false
                        )
                    else { continue }
                    agentResponding = responding
                    invalidateProviderStateAfterUnreadableRuntimeState()
                    scheduleRuntimeStateRefreshRetry(
                        for: nil,
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration
                    )
                    logger.warning(
                        "Service state reconciliation failed: \(error.localizedDescription, privacy: .public)"
                    )
                    updateStatusMessage()
                }
            }
        }
    }

    private func resetRuntimeStateRefreshRetries() {
        runtimeStateRefreshRetryGeneration &+= 1
        runtimeStateRefreshRetryTask?.cancel()
        runtimeStateRefreshRetryTask = nil
        runtimeStateRefreshRetryPolicy.reset()
    }

    private func scheduleRuntimeStateRefreshRetry(
        for runtimeState: AgentRuntimeState?,
        capturedWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64
    ) {
        guard runtimeStateRefreshRetryTask == nil,
            let delay = runtimeStateRefreshRetryPolicy.nextDelay(
                for: runtimeState,
                runtimeDNSDesired: runtimeDNSDesired,
                isStoppingDNS: isStoppingDNS,
                softwareUpdateSuspended: softwareUpdateSuspended,
                generationsAreCurrent: serviceWakeGenerationPolicy(
                    capturedWakeGeneration: capturedWakeGeneration,
                    capturedLifecycleGeneration: capturedLifecycleGeneration
                ).isCurrent
            )
        else { return }

        let retryGeneration = runtimeStateRefreshRetryGeneration
        runtimeStateRefreshRetryTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return
            }
            guard let self, runtimeStateRefreshRetryGeneration == retryGeneration else { return }
            runtimeStateRefreshRetryTask = nil
            guard !Task.isCancelled,
                runtimeDNSDesired,
                isCurrentServiceStateRefresh(
                    capturedWakeGeneration: capturedWakeGeneration,
                    capturedLifecycleGeneration: capturedLifecycleGeneration
                )
            else { return }
            scheduleServiceStateReconciliation(
                reason: "runtime-state-retry",
                resetRefreshRetries: false
            )
        }
    }

    private func isCurrentServiceStateRefresh(
        capturedWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64
    ) -> Bool {
        !Task.isCancelled && !isStoppingDNS && !softwareUpdateSuspended
            && serviceWakeGenerationPolicy(
                capturedWakeGeneration: capturedWakeGeneration,
                capturedLifecycleGeneration: capturedLifecycleGeneration
            ).isCurrent
    }

    private func applyRuntimeStatePresentation(
        _ presentation: RuntimeStatePresentation
    ) {
        providerState = presentation.providerState
        providerForwarding = presentation.forwarding
        resolverMode = presentation.resolverMode
    }

    /// The Agent's runtime snapshot is the only source of provider interception
    /// state. When it cannot be read the provider becomes `unknown`. The
    /// resolver's own state is left to its separate observation path.
    private func invalidateProviderStateAfterUnreadableRuntimeState() {
        applyRuntimeStatePresentation(RuntimeStatePresentationPolicy.unavailable)
    }

    private func serviceWakeGenerationPolicy(
        capturedWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64
    ) -> ServiceWakeGenerationPolicy {
        ServiceWakeGenerationPolicy(
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: serviceWakeupGate.currentGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: dnsLifecycleGeneration
        )
    }

    private func reconcileServiceRuntimeState(
        _ runtimeState: AgentRuntimeState,
        capturedWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64,
        authoritativeProxyEnabled: Bool,
        authoritativeFilterEnabled: Bool
    ) async {
        guard
            isCurrentServiceStateRefresh(
                capturedWakeGeneration: capturedWakeGeneration,
                capturedLifecycleGeneration: capturedLifecycleGeneration
            )
        else { return }
        guard persistedStateAvailability.allowsLifecycleActions else {
            requestPersistedStateRecoveryIfNeeded()
            return
        }

        let shouldKeepFilterEnabled = ContentFilterActivationPolicy(
            blockDohDotEnabled: blockDohDotEnabled,
            isEnabled: isEnabled,
            servicesRunning: runtimeState.servicesRunning,
            dnsProxyEnabled: true,
            captiveMode: CaptivePortalCompatibilityMode.from(
                fullBypassActive: runtimeState.captivePortalDetected,
                forwarding: runtimeState.forwarding
            ),
            licenseValid: isLicenseValid,
            filterEnabled: authoritativeFilterEnabled
        ).shouldKeepEnabled
        let policy = ServiceWakeReconciliationPolicy(
            runtimeState: runtimeState,
            runtimeDNSDesired: runtimeDNSDesired,
            isStoppingDNS: isStoppingDNS,
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: serviceWakeupGate.currentGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: dnsLifecycleGeneration,
            authoritativeProxyEnabled: authoritativeProxyEnabled,
            authoritativeFilterEnabled: authoritativeFilterEnabled,
            shouldKeepContentFilterEnabled: shouldKeepFilterEnabled,
            persistedStateAvailability: persistedStateAvailability
        )
        guard policy.shouldApply else { return }

        if policy.shouldStopUnexpectedResolver {
            stopResolverStartedWithoutEnabledPreference()
            return
        }

        extensionVersionStale =
            ExtensionVersionStalePolicy(
                runningVersion: runtimeState.proxyProviderVersion,
                bundledVersion: extensionManager.bundledExtensionVersion,
                proxyEnabled: authoritativeProxyEnabled,
                activationInProgress: extensionManager.isActivationInProgress
            ).isStale

        if runtimeState.proxyControlUnreachable == false || !runtimeDNSDesired {
            proxyControlBounceAttempts = 0
            proxyControlRecoveryExhausted = false
        }
        let recoveryPolicy = ProxyBounceRecoveryPolicy(
            outageReported: runtimeState.proxyControlUnreachable,
            runtimeDNSDesired: runtimeDNSDesired,
            servicesRunning: runtimeState.servicesRunning,
            proxyEnabled: authoritativeProxyEnabled,
            activationInProgress: extensionManager.isActivationInProgress,
            replacementDrainActive: extensionManager.isReplacementDrainActive,
            drainUnconfirmed: extensionManager.replacementDrainUnconfirmed,
            bounceInProgress: proxyControlBounceInProgress,
            attemptsMade: proxyControlBounceAttempts,
            lastAttemptAt: proxyControlLastBounceAt,
            now: Date()
        )
        switch recoveryPolicy.action {
        case .bounce:
            startProxyControlBounce()
            return
        case .surfaceRestartRequired:
            proxyControlRecoveryExhausted = true
        case .none:
            break
        }
        guard !proxyControlBounceInProgress else { return }

        switch policy.proxyAction {
        case .enable:
            let proxyResult = await enableProxyAndContentFilter(
                for: capturedLifecycleGeneration,
                expectedWakeGeneration: capturedWakeGeneration,
                enableContentFilterAfterProxy: false
            )
            guard persistedStateAvailability == .loaded,
                isCurrentServiceStateRefresh(
                    capturedWakeGeneration: capturedWakeGeneration,
                    capturedLifecycleGeneration: capturedLifecycleGeneration
                )
            else {
                if dnsLifecycleGeneration != capturedLifecycleGeneration {
                    await rollbackStaleProxyEnableIfNeeded(
                        from: capturedLifecycleGeneration
                    )
                }
                return
            }
            captivePortalDetected =
                proxyResult.captivePortalDetectedAfterResolveAttempt
            resolverMode = proxyResult.resolverModeText
            guard proxyResult == .enabled else {
                updateStatusMessage()
                return
            }
        case .disable:
            cancelPendingContentFilterEnable(clearNotice: false)
            await disableDNSProxyAfterServiceStop()
            guard
                isCurrentServiceStateRefresh(
                    capturedWakeGeneration: capturedWakeGeneration,
                    capturedLifecycleGeneration: capturedLifecycleGeneration
                )
            else { return }
        case .none:
            if authoritativeProxyEnabled {
                extensionActive = true
            }
        }

        guard
            isCurrentServiceStateRefresh(
                capturedWakeGeneration: capturedWakeGeneration,
                capturedLifecycleGeneration: capturedLifecycleGeneration
            )
        else { return }

        switch policy.contentFilterAction {
        case .enable:
            enableContentFilterInBackgroundIfNeeded(reason: "service state reconciliation")
        case .disable:
            cancelPendingContentFilterEnable(clearNotice: false)
            do {
                try await extensionManager.disableContentFilter()
            } catch {
                guard
                    isCurrentServiceStateRefresh(
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration
                    )
                else { return }
                logger.warning(
                    "Failed to disable Content Filter during service state reconciliation: \(error.localizedDescription, privacy: .public)"
                )
            }
        case .none:
            break
        }

        guard
            isCurrentServiceStateRefresh(
                capturedWakeGeneration: capturedWakeGeneration,
                capturedLifecycleGeneration: capturedLifecycleGeneration
            )
        else { return }
        updateStatusMessage()
    }

    /// Disable → wait for provider exit → enable. Forces launchd to remove and
    /// resubmit the provider job, restoring the proxy-control Mach endpoint
    /// lost in the sysext replacement race. Content Filter re-enable happens on
    /// the follow-up reconciliation.
    private func startProxyControlBounce() {
        proxyControlBounceInProgress = true
        proxyControlBounceAttempts += 1
        proxyControlLastBounceAt = Date()
        logger.warning(
            "Proxy control unreachable; bouncing DNS Proxy configuration (attempt \(self.proxyControlBounceAttempts, privacy: .public))"
        )
        let generation = dnsLifecycleGeneration
        proxyControlBounceTask = Task { @MainActor in
            defer {
                proxyControlBounceTask = nil
                proxyControlBounceInProgress = false
                scheduleServiceStateReconciliation(reason: "proxy-control-bounce-finished")
            }
            do {
                try await ProxyControlBounce.run(
                    isCurrent: { self.isCurrentDNSLifecycle(generation) },
                    disable: { try await self.extensionManager.disableProxy() },
                    waitForExit: {
                        let exited = await DNSProxyProviderProcessInspector.waitForProviderExit(timeout: 30)
                        if !exited {
                            self.logger.warning("Proxy control bounce: provider did not exit within 30s")
                        }
                    },
                    enable: { try await self.extensionManager.enableProxy() },
                    rollbackStaleEnable: {
                        await self.rollbackStaleProxyEnableIfNeeded(from: generation)
                    }
                )
            } catch {
                logger.error("Proxy control bounce failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    nonisolated func signalLicenseStatusWakeup() {
        guard licenseStatusWakeupGate.begin() else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let wakeGeneration = licenseStatusWakeupGate.complete()
            scheduleLicenseStatusReconciliation(
                wakeGeneration: wakeGeneration
            )
        }
    }

    private func scheduleLicenseStatusReconciliation(
        wakeGeneration: UInt64
    ) {
        licenseStatusWakeGeneration = wakeGeneration
        licenseStatusWakePending = true
        logger.info("License status changed notification received")
        guard licenseStatusWakeTask == nil else { return }

        licenseStatusWakeTask = Task { @MainActor [weak self] in
            guard let self else { return }
            defer { licenseStatusWakeTask = nil }

            while licenseStatusWakePending {
                licenseStatusWakePending = false
                let capturedWakeGeneration = licenseStatusWakeGeneration
                let capturedLifecycleGeneration = dnsLifecycleGeneration
                let result = await XPCClient.shared.getLicenseInfoAsync()

                switch result {
                case .success(let info):
                    let policy = licenseStatusWakeResponsePolicy(
                        info: info,
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration
                    )
                    guard
                        let responding = policy.agentRespondingUpdate(
                            forXPCSucceeded: true
                        )
                    else { continue }

                    agentResponding = responding
                    licenseInfo = info
                    await applyLicenseStatusWake(
                        policy,
                        capturedWakeGeneration: capturedWakeGeneration
                    )

                case .failure(let error):
                    let policy = licenseStatusWakeResponsePolicy(
                        info: licenseInfo ?? LicenseInfoLoadFailurePolicy.failClosedInfo(),
                        capturedWakeGeneration: capturedWakeGeneration,
                        capturedLifecycleGeneration: capturedLifecycleGeneration
                    )
                    guard
                        let responding = policy.agentRespondingUpdate(
                            forXPCSucceeded: false
                        )
                    else { continue }

                    agentResponding = responding
                    logger.warning(
                        "License status reconciliation failed: \(error.localizedDescription, privacy: .public)"
                    )
                    updateStatusMessage()
                }
            }
        }
    }

    private func licenseStatusWakeResponsePolicy(
        info: LicenseInfo,
        capturedWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64
    ) -> LicenseStatusWakeResponsePolicy {
        LicenseStatusWakeResponsePolicy(
            authoritativeInfo: info,
            isEnabled: isEnabled,
            isStoppingDNS: isStoppingDNS || softwareUpdateSuspended,
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: licenseStatusWakeupGate.currentGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: dnsLifecycleGeneration,
            persistedStateAvailability: persistedStateAvailability
        )
    }

    private func applyLicenseStatusWake(
        _ policy: LicenseStatusWakeResponsePolicy,
        capturedWakeGeneration: UInt64
    ) async {
        switch policy.lifecycleAction {
        case .none:
            updateStatusMessage()

        case .reconcile:
            if !runtimeDNSDesired {
                dnsLifecycleGeneration &+= 1
            }
            runtimeDNSDesired = true
            logger.info("License valid, reconciling resolver and proxy state")
            checkServicesStatus()
            updateStatusMessage()

        case .disable:
            if runtimeDNSDesired {
                dnsLifecycleGeneration &+= 1
            }
            runtimeDNSDesired = false
            let lifecycleGeneration = dnsLifecycleGeneration
            cancelPendingContentFilterEnable()

            if extensionManager.proxyEnabled {
                logger.warning("License invalid, disabling proxy")
                do {
                    try await extensionManager.disableProxy()
                } catch {
                    guard
                        isCurrentLicenseStatusWake(
                            capturedWakeGeneration,
                            lifecycleGeneration: lifecycleGeneration
                        )
                    else { return }
                    logger.error(
                        "Failed to disable proxy: \(error.localizedDescription, privacy: .public)"
                    )
                }
            }

            guard
                isCurrentLicenseStatusWake(
                    capturedWakeGeneration,
                    lifecycleGeneration: lifecycleGeneration
                )
            else { return }
            servicesRunning = false
            await disableContentFilterForLicenseStatusWake(
                capturedWakeGeneration: capturedWakeGeneration,
                lifecycleGeneration: lifecycleGeneration
            )
            guard
                isCurrentLicenseStatusWake(
                    capturedWakeGeneration,
                    lifecycleGeneration: lifecycleGeneration
                )
            else { return }
            updateStatusMessage()
        }
    }

    private func isCurrentLicenseStatusWake(
        _ wakeGeneration: UInt64,
        lifecycleGeneration: UInt64
    ) -> Bool {
        licenseStatusWakeupGate.currentGeneration == wakeGeneration
            && dnsLifecycleGeneration == lifecycleGeneration
            && !isStoppingDNS
    }

    private func disableContentFilterForLicenseStatusWake(
        capturedWakeGeneration: UInt64,
        lifecycleGeneration: UInt64
    ) async {
        guard
            isCurrentLicenseStatusWake(
                capturedWakeGeneration,
                lifecycleGeneration: lifecycleGeneration
            ),
            shouldDisableContentFilter
        else { return }

        do {
            try await extensionManager.disableContentFilter()
            guard
                isCurrentLicenseStatusWake(
                    capturedWakeGeneration,
                    lifecycleGeneration: lifecycleGeneration
                )
            else { return }
            logger.info("Content Filter disabled because license is not admissible")
            clearExtensionNoticeIfResolved()
        } catch {
            guard
                isCurrentLicenseStatusWake(
                    capturedWakeGeneration,
                    lifecycleGeneration: lifecycleGeneration
                )
            else { return }
            logger.warning(
                "Failed to disable Content Filter for license status: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    private func handleUpdateAvailable() {
        logger.info("Update available notification received")
        loadUpdateInfo(presentIfAvailable: true)
    }

    private func observeCaptivePortalNotifications() {
        let observer = Unmanaged.passUnretained(self).toOpaque()
        let center = CFNotificationCenterGetDarwinNotifyCenter()

        // Captive notifications only wake authoritative Agent reconciliation.
        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.captivePortalDetected,
            nil,
            .deliverImmediately
        )

        // The notification name never determines runtime state.
        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let viewModel = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                viewModel.signalServiceWakeup()
            },
            DarwinNotifications.captivePortalResolved,
            nil,
            .deliverImmediately
        )
    }

    private func checkAgentAndExtensionStatus() {
        guard !softwareUpdateSuspended else { return }
        guard persistedStateAvailability.allowsLifecycleActions else {
            requestPersistedStateRecoveryIfNeeded()
            updateStatusMessage()
            return
        }

        agentInstalled = agentInstaller.isInstalled()

        if !isEnabled {
            logger.info("Service is disabled (isEnabled=false)")
            statusMessage = "Ready"
            return
        }

        // Case 1: Agent not installed but isEnabled=true. This happens after
        // "Quit and Remove Services", so reinstall and start services.
        if !agentInstalled && agentInstaller.status != .enabled {
            logger.info("Agent not installed but isEnabled=true - installing and starting services...")
            statusMessage = "Starting services..."

            Task {
                enableDNS()  // This installs Agent and starts all services
            }
            return
        }

        // Case 2: Agent registered but not running (isEnabled=true)
        // This happens when agent process crashed or was killed
        if !agentInstalled && agentInstaller.status == .enabled && isEnabled {
            logger.info("Agent registered but not running (isEnabled=true) - attempting restart...")
            statusMessage = "Restarting agent..."
            let lifecycleGeneration = dnsLifecycleGeneration

            Task {
                do {
                    try await registerAgent()  // Will unregister and re-register
                    setAgentPermissionApprovalRequired(false)
                    agentInstalled = true
                    agentResponding = true
                    XPCClient.shared.resetConnection()

                    try await waitForAgentReady()
                    logger.info("Agent restarted successfully")

                    let loadOutcome = await performFreshPersistedStateLoad(
                        expectedLifecycleGeneration: lifecycleGeneration
                    )
                    guard loadOutcome == .loaded,
                        persistedStateAvailability == .loaded,
                        dnsLifecycleGeneration == lifecycleGeneration
                    else {
                        markPostRecoveryReconciliationPending(
                            after: loadOutcome,
                            lifecycleGeneration: lifecycleGeneration
                        )
                        requestPersistedStateRecoveryIfNeeded()
                        updateStatusMessage()
                        return
                    }
                    checkServicesStatus()

                    await ensureExtensionApproved()

                } catch AgentError.requiresApproval {
                    logger.warning("Agent requires approval")
                    setAgentPermissionApprovalRequired(true)
                    statusMessage = "Approval Required"
                } catch {
                    logger.error("Failed to restart agent: \(error.localizedDescription, privacy: .public)")
                    statusMessage = "Agent restart failed"
                }
            }
            return
        }

        // Case 3: Agent is installed and running - just ensure approvals
        let agentRequiresApproval = agentInstaller.requiresApproval()
        setAgentPermissionApprovalRequired(agentRequiresApproval)
        if agentRequiresApproval {
            agentInstaller.openSystemSettings()
        }
        Task {
            await ensureExtensionApproved()
        }
    }

    private func ensureExtensionApproved() async {
        await extensionManager.ensureApproved()
    }

    private func requestPersistedStateRecoveryIfNeeded() {
        guard !agentReplacementInProgress else { return }
        guard persistedStateAvailability.allowsRecoveryRequests else { return }
        persistedStateRecoveryCoordinator.requestEarlierRetry()
    }

    private func markPostRecoveryReconciliationPending(
        after outcome: PersistedStateLoadOutcome,
        lifecycleGeneration: UInt64
    ) {
        guard didCompleteAuthoritativeStartup,
            case .unavailable = outcome,
            dnsLifecycleGeneration == lifecycleGeneration
        else { return }

        postRecoveryReconciliation.markPending(
            lifecycleGeneration: lifecycleGeneration
        )
    }

    private func performFreshPersistedStateLoad(
        expectedLifecycleGeneration: UInt64? = nil
    ) async -> PersistedStateLoadOutcome {
        guard persistedStateAvailability != .invalidConfiguration else {
            return .invalidConfiguration
        }
        guard
            expectedLifecycleGeneration == nil
                || dnsLifecycleGeneration == expectedLifecycleGeneration
        else { return .superseded }

        persistedStateLoadGeneration &+= 1
        return await persistedStateRecoveryCoordinator.loadFresh()
    }

    private func performPersistedStateLoadAttempt(
        attempt: Int,
        expectedLoadGeneration: UInt64,
        expectedLifecycleGeneration: UInt64? = nil
    ) async -> PersistedStateLoadOutcome {
        guard !agentReplacementInProgress else { return .superseded }

        let mutationGenerationAtStart = persistedStateMutationGeneration
        let lifecycleGenerationAtStart =
            expectedLifecycleGeneration ?? dnsLifecycleGeneration
        if authoritativeStateRecoveryStartedAt == nil {
            authoritativeStateRecoveryStartedAt = ProcessInfo.processInfo.systemUptime
        }
        if attempt > 1 {
            logger.info(
                "Retrying authoritative state load: attempt=\(attempt, privacy: .public)"
            )
        }

        isLoading = true
        persistedStateAvailability = .loading
        defer { isLoading = false }

        let loadResult = await XPCClient.shared.getFullConfigAsync()

        guard !agentReplacementInProgress else { return .superseded }
        guard persistedStateLoadGeneration == expectedLoadGeneration else {
            return .superseded
        }
        guard dnsLifecycleGeneration == lifecycleGenerationAtStart else {
            return .superseded
        }

        guard
            PersistedStateResponsePolicy.canApply(
                requestGeneration: mutationGenerationAtStart,
                currentGeneration: persistedStateMutationGeneration,
                coordinatorIsIdle: fullConfigSaveCoordinator.isIdle
            )
        else {
            logger.info(
                "Ignoring stale persisted state after a newer local configuration change"
            )
            return .superseded
        }

        switch loadResult {
        case .success(let config):
            agentResponding = true
            return applyLoadedPersistedConfig(
                config,
                agentResponding: true,
                sourceDescription: "Authoritative state loaded"
            )

        case .failure(let error):
            let decision = PersistedStateLoadPolicy.decision(
                for: error,
                canUseStateFileFallback: agentInstaller.canUseStateFileFallback()
            )
            switch decision {
            case .retry(let reason):
                return markPersistedStateUnavailable(reason)

            case .useStateFileFallback:
                agentResponding = false
                let stateFile = loadPersistedStateFromFile()
                if AgentSetupRequirementPolicy.requiresAgentSetup(
                    stateFile: stateFile,
                    supportDirectoryExists: FileManager.default.fileExists(
                        atPath: PathResolver.applicationSupportDir.path
                    )
                ) {
                    persistedStateAvailability = .agentSetupRequired
                    return .agentSetupRequired
                }
                switch stateFile {
                case .valid(let config):
                    return applyLoadedPersistedConfig(
                        config,
                        agentResponding: false,
                        sourceDescription: "State loaded from file (agent service unavailable)"
                    )
                case .invalidConfiguration:
                    persistedStateAvailability = .invalidConfiguration
                    return .invalidConfiguration
                case .missing, .ioFailure:
                    return markPersistedStateUnavailable(
                        unavailableReason(for: error)
                    )
                }

            case .invalidConfiguration:
                agentResponding = true
                persistedStateAvailability = .invalidConfiguration
                logger.error(
                    "Authoritative state rejected: \(error.localizedDescription, privacy: .public)"
                )
                return .invalidConfiguration
            }
        }
    }

    private func applyLoadedPersistedConfig(
        _ config: [String: Any],
        agentResponding: Bool,
        sourceDescription: String
    ) -> PersistedStateLoadOutcome {
        guard applyPersistedConfig(config) else {
            persistedStateAvailability = .invalidConfiguration
            return .invalidConfiguration
        }

        fullConfigSaveCoordinator.adopt(loaded: config)
        persistedStateAvailability = .loaded
        self.agentResponding = agentResponding
        logger.info("\(sourceDescription, privacy: .public)")
        return .loaded
    }

    private func markPersistedStateUnavailable(
        _ reason: PersistedStateUnavailableReason
    ) -> PersistedStateLoadOutcome {
        persistedStateAvailability = .unavailable
        agentResponding = false
        return .unavailable(reason)
    }

    private func unavailableReason(
        for error: XPCError
    ) -> PersistedStateUnavailableReason {
        switch error {
        case .connectionInterrupted:
            return .connectionInterrupted
        default:
            return .agentNotResponding
        }
    }

    private func handlePersistedStateLoadCompletion(
        _ outcome: PersistedStateLoadOutcome,
        attempt: Int
    ) {
        switch outcome {
        case .loaded:
            if didLogAuthoritativeStateUnavailable,
                let startedAt = authoritativeStateRecoveryStartedAt
            {
                let elapsed =
                    ProcessInfo.processInfo.systemUptime - startedAt
                let elapsedDescription = String(format: "%.1f", elapsed)
                logger.info(
                    "Authoritative state recovered after \(elapsedDescription, privacy: .public)s"
                )
            }
            authoritativeStateRecoveryStartedAt = nil
            didLogAuthoritativeStateUnavailable = false
            didResetConnectionForUnreachableAgent = false
            updateInfoLoader.retryPendingPresentation()
            completeAuthoritativeStartupIfPossible()
            reconcilePostRecoveryIfNeeded(after: outcome)
            if !blocklistSettingsLoaded && !isLoadingBlocklist {
                loadBlocklistSettings()
            }
            updateStatusMessage()

        case .unavailable(let reason):
            if !didLogAuthoritativeStateUnavailable {
                let reasonDescription: String
                switch reason {
                case .timeout:
                    reasonDescription = "timeout"
                case .agentNotResponding:
                    reasonDescription = "agent not responding"
                case .connectionInterrupted:
                    reasonDescription = "connection interrupted"
                case .stateReadFailure:
                    reasonDescription = "agent could not read state.json"
                }
                logger.warning(
                    "Authoritative state unavailable: \(reasonDescription, privacy: .public); preserving runtime state"
                )
                didLogAuthoritativeStateUnavailable = true
            }

            let startedAt =
                authoritativeStateRecoveryStartedAt
                ?? ProcessInfo.processInfo.systemUptime
            let recoveryPolicy = AgentUpgradeRecoveryPolicy(
                reason: reason,
                elapsed: ProcessInfo.processInfo.systemUptime - startedAt,
                agentRegistered: agentInstaller.isRegistered(),
                authoritativeStartupCompleted: didCompleteAuthoritativeStartup,
                didResetConnection: didResetConnectionForUnreachableAgent,
                didAttemptReplacement:
                    didAttemptAgentReplacementForUnreachableState
            )
            switch recoveryPolicy.action {
            case .resetConnection:
                didResetConnectionForUnreachableAgent = true
                logger.warning(
                    "Agent unreachable during startup; resetting XPC connection"
                )
                XPCClient.shared.resetConnection()
                requestPersistedStateRecoveryIfNeeded()

            case .replaceAgent:
                didAttemptAgentReplacementForUnreachableState = true
                logger.warning(
                    "Agent unreachable during startup for 30s; replacing bundled agent"
                )
                Task { @MainActor [weak self] in
                    await self?.restartAgentForUpdate(
                        trigger: .unreachableState
                    )
                }

            case .none:
                break
            }
            updateStatusMessage()

        case .invalidConfiguration:
            authoritativeStateRecoveryStartedAt = nil
            didLogAuthoritativeStateUnavailable = false
            didResetConnectionForUnreachableAgent = false
            reconcilePostRecoveryIfNeeded(after: outcome)
            updateStatusMessage()

        case .agentSetupRequired:
            authoritativeStateRecoveryStartedAt = nil
            didLogAuthoritativeStateUnavailable = false
            didResetConnectionForUnreachableAgent = false
            logger.notice(
                "Agent not installed and no saved configuration: waiting for the user to enable protection"
            )
            updateStatusMessage()

        case .superseded:
            logger.debug(
                "Authoritative state load superseded: attempt=\(attempt, privacy: .public)"
            )
            updateStatusMessage()
        }
    }

    private func reconcilePostRecoveryIfNeeded(
        after outcome: PersistedStateLoadOutcome
    ) {
        guard
            postRecoveryReconciliation.consumeIfCurrent(
                outcome: outcome,
                currentLifecycleGeneration: dnsLifecycleGeneration
            )
        else { return }
        guard didCompleteAuthoritativeStartup,
            persistedStateAvailability == .loaded
        else { return }

        checkAgentAndExtensionStatus()
        checkServicesStatus()
    }

    private func completeAuthoritativeStartupIfPossible() {
        guard startupAuxiliaryLoadsStarted,
            persistedStateAvailability == .loaded,
            !didCompleteAuthoritativeStartup
        else { return }

        didCompleteAuthoritativeStartup = true
        checkAgentAndExtensionStatus()
        checkServicesStatus()
        Task { @MainActor [weak self] in
            await self?.checkBinaryMismatch()
        }
    }

    private func applyPersistedConfig(_ config: [String: Any]) -> Bool {
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(
                config
            )
        else {
            logger.error(
                "Persisted state rejected: malformed customZones or dnsOverrides"
            )
            return false
        }

        isApplyingPersistedState = true
        defer { isApplyingPersistedState = false }
        applyConfig(validated.normalizedConfig, dnsPolicy: validated)
        return true
    }

    private func applyConfig(
        _ config: [String: Any],
        dnsPolicy: ValidatedDNSPolicyConfig
    ) {
        isEnabled = config["isEnabled"] as? Bool ?? false
        dnssecEnabled = config["dnssecEnabled"] as? Bool ?? true
        logQueriesEnabled = config["logQueriesEnabled"] as? Bool ?? false
        logRepliesEnabled = config["logRepliesEnabled"] as? Bool ?? false
        prefetchEnabled = config["prefetchEnabled"] as? Bool ?? true
        serveExpiredEnabled = config["serveExpiredEnabled"] as? Bool ?? true
        queryHistorySettings = QueryHistorySettings.persisted(in: config)
        let rawProviders =
            config["dohProviders"] as? [String] ?? DoHProviderID.defaultProviders.map(\.rawValue)
        dohProviders = Set(DoHProviderID.canonicalized(rawProviders))

        let rawMode = config["dohDispatchMode"] as? String
        dohDispatchMode = rawMode.flatMap(DoHDispatchMode.init(rawValue:)) ?? .defaultMode
        dnsAnswerRefinementEnabled = config["dnsAnswerRefinementEnabled"] as? Bool ?? true
        blockDohDotEnabled = config["blockDohDotEnabled"] as? Bool ?? false

        customZones = dnsPolicy.customZones
        dnsOverrides = dnsPolicy.dnsOverrides

        if let allowlistData = config["allowlist"] as? [[String: Any]] {
            allowedDomains = AllowedDomain.parseArray(allowlistData)
        }

        if !isEnablingDNS && !isStoppingDNS && !softwareUpdateSuspended {
            runtimeDNSDesired = isEnabled
        }
    }

    func buildFullConfigSnapshot() -> [String: Any] {
        FullConfigSnapshotBuilder.build(
            isEnabled: isEnabled,
            dnssecEnabled: dnssecEnabled,
            logQueriesEnabled: logQueriesEnabled,
            logRepliesEnabled: logRepliesEnabled,
            prefetchEnabled: prefetchEnabled,
            serveExpiredEnabled: serveExpiredEnabled,
            dohProviders: dohProviders,
            dohDispatchMode: dohDispatchMode,
            dnsAnswerRefinementEnabled: dnsAnswerRefinementEnabled,
            blockDohDotEnabled: blockDohDotEnabled,
            queryHistory: queryHistorySettings,
            customZones: customZones,
            dnsOverrides: dnsOverrides,
            allowedDomains: allowedDomains
        )
    }

    private func saveFullConfigToDaemon() {
        FullConfigSaveBoundary.performIfAllowed(
            availability: persistedStateAvailability,
            isApplyingPersistedState: isApplyingPersistedState
        ) {
            persistedStateMutationGeneration &+= 1
            fullConfigSaveCoordinator.enqueue(buildFullConfigSnapshot())
        }
    }

    /// A save that never lands must be visible: the reverted row alone does not
    /// tell the user the Agent refused or never confirmed the change.
    private func handleConfigSaveOutcome(_ outcome: FullConfigSaveOutcome) {
        configSaveFailureMessage = outcome.failureMessage

        switch outcome {
        case .committed:
            break
        case .stalled:
            logger.warning("Configuration save stalled without an agent reply")
        case .rejected(let reason):
            logger.error(
                "Agent rejected the configuration save: \(reason?.rawValue ?? "unspecified", privacy: .public)"
            )
        case .recovered:
            logger.info("Stalled configuration save accounted for after reload")
        case .conflict:
            logger.warning(
                "Configuration save dropped: the configuration changed elsewhere"
            )
        }
    }

    /// Fallback when the agent is unavailable.
    private func saveStateToFile(
        _ config: [String: Any],
        expectedRevision: ConfigRevision
    ) -> ConfigRevision? {
        let persistedRevision = RevisionAwareConfigFileStore.save(
            snapshot: config,
            expectedRevision: expectedRevision,
            stateFile: PathResolver.stateFile
        )
        if persistedRevision != nil {
            logger.info("State saved to file (fallback)")
        } else {
            logger.warning("Fallback state save rejected")
        }
        return persistedRevision
    }

    // MARK: - DNS Control
    func toggleDNS() {
        guard persistedStateAvailability.allowsUserEnable else {
            requestPersistedStateRecoveryIfNeeded()
            updateStatusMessage()
            return
        }
        if isEnabled {
            disableDNS()
        } else {
            enableDNS()
        }
    }

    /// Returns true only when an Enable attempt started. `asFreshInstallSetup`
    /// starts the fresh install setup, whose outcome gets one alert.
    @discardableResult
    func enableDNS(asFreshInstallSetup: Bool = false) -> Bool {
        guard !isEnablingDNS, !isStoppingDNS, !softwareUpdateSuspended else {
            logger.info("DNS enable already in progress")
            return false
        }
        guard persistedStateAvailability.allowsUserEnable else {
            requestPersistedStateRecoveryIfNeeded()
            updateStatusMessage()
            return false
        }

        if LicenseEnableGatePolicy.blocksEnable(licenseInfo, agentInstalled: agentInstalled),
            let info = licenseInfo
        {
            runtimeDNSDesired = false
            resumeDNSAfterProxyApproval = false
            logger.warning("Cannot enable service: \(info.statusDescription, privacy: .public)")
            statusMessage = info.statusDescription
            return false
        }

        logger.info("Enabling DNS protection")
        statusMessage = "Starting services..."
        let continuesSetup = FreshInstallSetupPolicy.continuesSetup(
            startedAsFreshInstall: asFreshInstallSetup,
            setupGeneration: freshInstallSetupGeneration,
            currentGeneration: dnsLifecycleGeneration
        )
        dnsLifecycleGeneration &+= 1
        let lifecycleGeneration = dnsLifecycleGeneration
        freshInstallSetupGeneration = continuesSetup ? lifecycleGeneration : nil
        if continuesSetup {
            freshInstallSetupOutcome = nil
            freshInstallSetupFailureMessage = nil
        }
        runtimeDNSDesired = true
        isEnablingDNS = true
        resumeDNSAfterProxyApproval = false

        Task { @MainActor in
            defer { reportFreshInstallSetupOutcome(for: lifecycleGeneration) }
            defer { isEnablingDNS = false }
            defer { firstRunApprovedStep = nil }
            do {
                // 1. Install agent if needed
                if !agentInstalled {
                    try await installAgent()
                }

                guard persistedStateAvailability.allowsUserEnable,
                    isCurrentDNSLifecycle(lifecycleGeneration)
                else { return }

                // 2. Load existing configuration before changing runtime state.
                let loadOutcome = await performFreshPersistedStateLoad(
                    expectedLifecycleGeneration: lifecycleGeneration
                )
                guard loadOutcome == .loaded,
                    persistedStateAvailability == .loaded,
                    isCurrentDNSLifecycle(lifecycleGeneration)
                else {
                    requestPersistedStateRecoveryIfNeeded()
                    updateStatusMessage()
                    return
                }

                // 3. Configure System Extension before starting resolver. DNS Proxy enables after resolver start.
                if continuesSetup {
                    await awaitFirstRunContinue(
                        on: .networkExtension,
                        stepDone: extensionManager.systemExtensionActivated || extensionManager.isActive,
                        generation: lifecycleGeneration
                    )
                    guard persistedStateAvailability == .loaded,
                        isCurrentDNSLifecycle(lifecycleGeneration)
                    else { return }
                }
                statusMessage = "Activating extension..."
                try await ensureDNSProxyConfigured(setupGeneration: continuesSetup ? lifecycleGeneration : nil)
                guard persistedStateAvailability == .loaded,
                    isCurrentDNSLifecycle(lifecycleGeneration)
                else { return }
                try await disableDNSProxyBeforeResolverStartIfNeeded()
                guard persistedStateAvailability == .loaded,
                    isCurrentDNSLifecycle(lifecycleGeneration)
                else { return }

                // The setup asks for notifications before the resolver starts,
                // which can raise the local network request.
                var notificationsHandled = false
                if continuesSetup {
                    await refreshNotificationAuthorization()
                    await awaitFirstRunContinue(
                        on: .notifications,
                        stepDone: notificationsDecided || firstRunNotificationsSkipped,
                        generation: lifecycleGeneration
                    )
                    guard persistedStateAvailability == .loaded,
                        isCurrentDNSLifecycle(lifecycleGeneration)
                    else { return }
                    notificationsHandled = await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)
                    guard persistedStateAvailability == .loaded,
                        isCurrentDNSLifecycle(lifecycleGeneration)
                    else { return }
                }

                // 4. Start the resolver
                let startSuccess: Bool
                switch await XPCClient.shared.startResolverAsync() {
                case .success(let success):
                    startSuccess = success
                case .failure(let error):
                    logger.error("Failed to start services: \(error.localizedDescription, privacy: .public)")
                    startSuccess = false
                }

                guard persistedStateAvailability == .loaded,
                    isCurrentDNSLifecycle(lifecycleGeneration)
                else {
                    if startSuccess {
                        await stopServicesAfterStaleStart(
                            from: lifecycleGeneration,
                            stopWhenPersistedStateUnavailable: true
                        )
                    }
                    return
                }

                if startSuccess {
                    let proxyResult = await enableProxyAndContentFilter(for: lifecycleGeneration)
                    guard persistedStateAvailability == .loaded,
                        isCurrentDNSLifecycle(lifecycleGeneration)
                    else {
                        await stopServicesAfterStaleStart(
                            from: lifecycleGeneration,
                            stopWhenPersistedStateUnavailable: true
                        )
                        return
                    }
                    resolverMode = proxyResult.resolverModeText
                    guard proxyResult != .inactive else {
                        logger.error("Resolver started but DNS Proxy is not enabled")
                        servicesRunning = false
                        agentResponding = true
                        _ = await XPCClient.shared.stopResolverAsync(force: false)
                        runtimeDNSDesired = resumeDNSAfterProxyApproval
                        statusMessage = proxyResult.resolverModeText
                        return
                    }

                    logger.info("DNS protection enabled successfully")
                    resumeDNSAfterProxyApproval = false
                    isEnabled = true
                    servicesRunning = true
                    agentResponding = true

                    updateStatusMessage()
                    // Asked only once protection runs, so a fresh install sees no macOS
                    // prompt before Turn On. Later calls return the stored answer silently.
                    // A setup that waited already asked before the resolver started,
                    // and one the user skipped asks at a later launch.
                    if !notificationsHandled {
                        requestNotificationPermission()
                    }

                    // 5. Register app to launch at login. `SMAppService.register()` validates
                    // code signatures through Security on the calling thread, so keep it off main.
                    do {
                        try await Task.detached { try SMAppService.mainApp.register() }.value
                        logger.info("App registered as login item")
                    } catch {
                        logger.warning(
                            "Failed to register app as login item: \(error.localizedDescription, privacy: .public)"
                        )
                    }
                } else {
                    logger.error("Failed to start services")
                    runtimeDNSDesired = false
                    resumeDNSAfterProxyApproval = false
                    isEnabled = false
                    servicesRunning = false

                    // Get license info to show specific error. The lookup must stay
                    // bounded: an unresponsive Agent would otherwise suspend this task
                    // forever and leave `isEnablingDNS` raised for the whole session.
                    // A failed lookup means unknown, never fail-closed. A fail-closed
                    // info here would make the guard above reject every later attempt.
                    switch await XPCClient.shared.getLicenseInfoAsync() {
                    case .success(let info):
                        licenseInfo = info
                        agentResponding = true
                    case .failure(let error):
                        logger.warning(
                            "License info unavailable: \(error.localizedDescription, privacy: .public)"
                        )
                        licenseInfo = nil
                        agentResponding = false
                    }
                    updateStatusMessage()
                }

            } catch AgentError.requiresApproval {
                guard isCurrentDNSLifecycle(lifecycleGeneration) else { return }
                resumeDNSAfterProxyApproval = false
                logger.warning("Agent requires user approval")
                statusMessage = "Approval Required"
                setAgentPermissionApprovalRequired(true)
                agentInstaller.openSystemSettings()

            } catch is CancellationError {
                logger.info("DNS enable stopped before saving the DNS Proxy configuration")

            } catch {
                guard isCurrentDNSLifecycle(lifecycleGeneration) else { return }
                logger.error("Failed to enable DNS: \(error.localizedDescription, privacy: .public)")
                refreshPermissionApprovalState()
                if case ExtensionError.activationRequiresReboot = error {
                    resumeDNSAfterProxyApproval = false
                    setExtensionNotice(.restartRequired)
                } else if needsPermissionApproval {
                    resumeDNSAfterProxyApproval = extensionManager.needsUserApproval
                    extensionNotice.applyApprovalStatus(
                        proxyNeedsApproval: extensionManager.needsUserApproval,
                        filterNeedsApproval: filterManager.needsUserApproval
                    )
                    updateStatusMessage()
                } else {
                    resumeDNSAfterProxyApproval = false
                    statusMessage = "Failed: \(error.localizedDescription)"
                }
            }
        }
        return true
    }

    func disableDNS() {
        guard !isStoppingDNS, !softwareUpdateSuspended else { return }

        logger.info("Disabling DNS protection")
        statusMessage = "Stopping..."
        proxyControlBounceTask?.cancel()
        dnsLifecycleGeneration &+= 1
        runtimeDNSDesired = false
        isStoppingDNS = true
        resumeDNSAfterProxyApproval = false
        cancelPendingContentFilterEnable()

        Task { @MainActor in
            defer { isStoppingDNS = false }

            let teardown = await DNSDisableIntentPolicy.execute { step in
                switch step {
                case .persistDisabledIntent:
                    self.isEnabled = false
                    return true
                case .disableDNSProxy:
                    return await self.disableDNSProxyForStop()
                case .disableContentFilter:
                    return await self.disableContentFilterForStopIfNeeded()
                }
            }
            guard teardown == .completed else { return }
            // The snapshot is refreshed only while protection is wanted, so drop it now.
            self.invalidateProviderStateAfterUnreadableRuntimeState()

            var resolverStopped = false
            switch await XPCClient.shared.stopResolverAsync(force: false) {
            case .success(let success):
                resolverStopped = success
                logger.info("Services stopped: \(success, privacy: .public)")
            case .failure(let error):
                logger.warning(
                    "Resolver stop did not complete: \(error.localizedDescription, privacy: .public)"
                )
            }

            await MainActor.run {
                if resolverStopped {
                    self.servicesRunning = false
                    self.statusMessage = "Ready"
                } else {
                    self.statusMessage = "Stopping DNS failed - retrying"
                }
            }

            guard !resolverStopped else { return }
            await reconcileAfterFailedResolverStop()
        }
    }

    /// Retries a failed resolver stop once, then reconciles against the
    /// Agent's authoritative runtime state rather than assuming success.
    private func reconcileAfterFailedResolverStop() async {
        if case .success(true) = await XPCClient.shared.stopResolverAsync(force: true) {
            await MainActor.run {
                self.servicesRunning = false
                self.statusMessage = "Ready"
            }
            return
        }

        logger.error("Resolver stop failed after forced retry")
        checkServicesStatus()
    }

    /// Stops all services, uninstalls the Agent and terminates the app.
    /// An in-flight Agent install finishes before the uninstall.
    /// `servicesRemovalRequested` holds for the whole removal, so closing the
    /// first-run window meanwhile cannot register the Agent again, and an
    /// aborted quit leaves the first-run trial step available.
    func quitCompletely() async {
        guard !isStoppingDNS, !softwareUpdateSuspended else { return }
        servicesRemovalRequested = true
        defer { servicesRemovalRequested = false }

        logger.info("Quitting MacDNS completely...")
        statusMessage = "Shutting down..."
        proxyControlBounceTask?.cancel()
        dnsLifecycleGeneration &+= 1
        runtimeDNSDesired = false
        isStoppingDNS = true
        resumeDNSAfterProxyApproval = false
        defer { isStoppingDNS = false }
        cancelPendingContentFilterEnable()
        _ = try? await runningAgentInstall?.value

        // 1. Disable DNS Proxy FIRST (DNS queries pass through immediately)
        guard await disableDNSProxyForStop() else { return }
        guard await disableContentFilterForStopIfNeeded() else { return }

        // 2. Stop the resolver without changing isEnabled. state.json restores the same ON/OFF preference.
        // Uninstalling the Agent while the resolver still holds port 5335 would
        // strand it, so a failed stop aborts the quit with DNS left fail-open.
        // An unregistered Agent runs no resolver.
        var resolverStopped = false
        if !agentInstaller.isRegistered() {
            resolverStopped = true
        } else if case .success(true) = await XPCClient.shared.stopResolverAsync(force: false) {
            resolverStopped = true
        } else if case .success(true) = await XPCClient.shared.stopResolverAsync(force: true) {
            resolverStopped = true
        }

        guard resolverStopped else {
            logger.error("Quit aborted: resolver could not be stopped")
            statusMessage = "Shutdown failed - DNS Proxy disabled"
            checkServicesStatus()
            return
        }
        servicesRunning = false

        // 3. Unregister and stop Agent
        do {
            try await agentInstaller.uninstall()
            agentInstalled = false
            logger.info("Agent unregistered")
        } catch {
            logger.error("Failed to uninstall agent: \(error.localizedDescription, privacy: .public)")
        }

        // 4. Unregister app from login items
        do {
            try await appLoginItem.unregister()
            logger.info("App unregistered from login items")
        } catch {
            logger.warning(
                "Failed to unregister app from login items: \(error.localizedDescription, privacy: .public)"
            )
        }

        // 5. Reset XPC connection
        XPCClient.shared.resetConnection()

        // 6. Terminate app
        await MainActor.run {
            NSApplication.shared.terminate(nil)
        }
    }

    private func performSoftwareUpdateStop(_ step: SoftwareUpdateLifecycle.StopStep) async -> Bool {
        switch step {
        case .disableDNSProxy:
            guard !isStoppingDNS, !isEnablingDNS, !isAutoStartingServices,
                !isUpdatingAgent, runningAgentInstall == nil, fullConfigSaveCoordinator.isIdle
            else {
                logger.warning("Update installation deferred while a service or configuration change is pending")
                return false
            }
            agentWasRegisteredBeforeSoftwareUpdate = agentInstaller.isRegistered()
            runtimeWasDesiredBeforeSoftwareUpdate = runtimeDNSDesired
            proxyControlBounceTask?.cancel()
            softwareUpdateSuspended = true
            resetRuntimeStateRefreshRetries()
            dnsLifecycleGeneration &+= 1
            runtimeDNSDesired = false
            resumeDNSAfterProxyApproval = false
            cancelPendingContentFilterEnable()
            statusMessage = "Preparing update..."
            logger.info("Preparing software update: releasing DNS traffic before stopping the Agent")
            return await disableDNSProxyForStop()
        case .disableContentFilter:
            return await disableContentFilterForStopIfNeeded()
        case .unregisterAgent:
            do {
                // launchd sends SIGTERM and waits for the Agent's resolver shutdown to finish.
                try await agentInstaller.uninstall()
                XPCClient.shared.resetConnection()
                agentInstalled = false
                agentResponding = false
                servicesRunning = false
                invalidateProviderStateAfterUnreadableRuntimeState()
                logger.info("Software update ready: Agent terminated and XPC connection cleared")
                return true
            } catch {
                logger.error("Update preparation failed: \(error.localizedDescription, privacy: .public)")
                statusMessage = "Update preparation failed"
                return false
            }
        }
    }

    private func restoreAfterCancelledSoftwareUpdate() async {
        guard softwareUpdateSuspended else { return }
        defer {
            softwareUpdateSuspended = false
            runtimeDNSDesired = runtimeWasDesiredBeforeSoftwareUpdate
            dnsLifecycleGeneration &+= 1
            requestPersistedStateRecoveryIfNeeded()
            checkAgentAndExtensionStatus()
            checkServicesStatus()
        }
        logger.info("Update did not finish: restoring the previous Agent registration")
        guard agentWasRegisteredBeforeSoftwareUpdate else { return }
        do {
            try await registerAgent()
            XPCClient.shared.resetConnection()
            try await waitForAgentReady(timeout: 10)
            agentInstalled = true
            agentResponding = true
        } catch {
            logger.error(
                "Failed to restore Agent after update cancellation: \(error.localizedDescription, privacy: .public)")
            statusMessage = "Could not restore services after update"
        }
    }

    // MARK: - Agent Ready Check

    /// Waits for the agent to become ready by polling XPC until it responds.
    /// Each probe is capped by the remaining budget so the overall deadline
    /// holds even when a single XPC call never answers.
    private func waitForAgentReady(timeout: TimeInterval = 5.0) async throws {
        let startTime = Date()
        let isReady = await AgentReadyWaitPolicy.waitUntilReady(
            policy: AgentReadyWaitPolicy(timeout: timeout, pollInterval: 0.1),
            elapsed: { Date().timeIntervalSince(startTime) },
            probe: { budget in
                switch await XPCClient.shared.getFullConfigAsync(timeout: budget) {
                case .success:
                    return true
                case .failure:
                    return false
                }
            },
            sleep: { seconds in
                try? await Task.sleep(
                    nanoseconds: UInt64(seconds * 1_000_000_000)
                )
            }
        )

        if isReady {
            logger.info("Agent is ready and responding to XPC")
            return
        }

        logger.error("Timeout waiting for agent to become ready")
        throw AgentError.registrationFailed(
            NSError(
                domain: "MacDNS", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Agent did not become ready in time"]))
    }

    // MARK: - Binary Mismatch Detection

    /// Checks if the running agent binary matches the embedded one.
    /// If there's a mismatch (e.g., after app update or rebuild), restarts the agent.
    func checkBinaryMismatch() async {
        guard !softwareUpdateSuspended else { return }
        guard persistedStateAvailability.allowsLifecycleActions else {
            requestPersistedStateRecoveryIfNeeded()
            return
        }

        guard agentInstaller.isInstalled() else {
            // Agent not running - will be installed separately, not updated
            logger.debug("Agent not installed, skipping binary mismatch check")
            return
        }

        guard let embeddedHash = BinaryHasher.sha256(ofFileAt: embeddedAgentPath) else {
            logger.warning("Failed to calculate embedded agent hash")
            return
        }

        guard let runningHash = await XPCClient.shared.getAgentBinaryHash() else {
            // A running agent (launchctl confirmed) without getAgentBinaryHash is
            // an old build that needs the update.
            logger.warning("Agent doesn't support binary hash check - updating old agent")
            await restartAgentForUpdate(trigger: .binaryMismatch)
            return
        }

        if embeddedHash != runningHash {
            logger.warning(
                "Binary mismatch: embedded=\(embeddedHash.prefix(8), privacy: .public)..., running=\(runningHash.prefix(8), privacy: .public)..."
            )
            await restartAgentForUpdate(trigger: .binaryMismatch)
        }
    }

    private func replaceRegisteredAgent() async throws {
        agentReplacementInProgress = true
        defer { agentReplacementInProgress = false }

        // Joining an install in flight would skip the unregistration, and an
        // Agent that is already running is never registered again.
        while let running = agentInstallSerializer.running {
            _ = try? await running.value
        }
        try await agentInstallSerializer.run { [self] in
            try await agentInstaller.uninstall()
            XPCClient.shared.resetConnection()
            try await agentInstaller.install()
        }
        setAgentPermissionApprovalRequired(false)
        agentInstalled = true
        XPCClient.shared.resetConnection()

        try await waitForAgentReady(timeout: 10)
    }

    /// Replaces the registered agent after a binary mismatch or a bounded
    /// initial-startup failure to load authoritative state.
    private func restartAgentForUpdate(trigger: AgentUpdateTrigger) async {
        guard !isUpdatingAgent, !softwareUpdateSuspended else { return }

        switch trigger {
        case .binaryMismatch:
            guard persistedStateAvailability.allowsLifecycleActions else {
                requestPersistedStateRecoveryIfNeeded()
                return
            }
        case .unreachableState:
            guard !didCompleteAuthoritativeStartup,
                persistedStateAvailability.allowsRecoveryRequests,
                agentInstaller.isRegistered()
            else { return }
        }

        logger.info(
            "Restarting agent for update: trigger=\(trigger.rawValue, privacy: .public)"
        )

        isUpdatingAgent = true
        defer {
            isUpdatingAgent = false
            requestPersistedStateRecoveryIfNeeded()
        }
        statusMessage = "Updating agent..."
        let lifecycleGeneration = dnsLifecycleGeneration

        do {
            try await replaceRegisteredAgent()

            // Reload state from the newly registered agent.
            let loadOutcome = await performFreshPersistedStateLoad(
                expectedLifecycleGeneration: lifecycleGeneration
            )
            guard loadOutcome == .loaded,
                persistedStateAvailability == .loaded,
                dnsLifecycleGeneration == lifecycleGeneration
            else {
                markPostRecoveryReconciliationPending(
                    after: loadOutcome,
                    lifecycleGeneration: lifecycleGeneration
                )
                requestPersistedStateRecoveryIfNeeded()
                updateStatusMessage()
                return
            }

            // Restore DNS from the freshly loaded authoritative state.
            if isEnabled {
                guard persistedStateAvailability == .loaded,
                    dnsLifecycleGeneration == lifecycleGeneration
                else { return }

                logger.info("Restoring DNS state after agent update")
                // Start services since agent restored from state.json
                let success: Bool
                switch await XPCClient.shared.startResolverAsync() {
                case .success(let didStart):
                    success = didStart
                case .failure(let error):
                    logger.error(
                        "Failed to restart services after agent update: \(error.localizedDescription, privacy: .public)"
                    )
                    success = false
                }

                guard persistedStateAvailability == .loaded,
                    dnsLifecycleGeneration == lifecycleGeneration
                else {
                    if success {
                        await stopServicesAfterStaleStart(
                            from: lifecycleGeneration,
                            stopWhenPersistedStateUnavailable: true
                        )
                    }
                    return
                }

                if success {
                    logger.info("Services restarted after agent update")
                    servicesRunning = true
                    agentResponding = true
                } else {
                    servicesRunning = false
                }
            }

            logger.info("Agent update completed successfully")
            updateStatusMessage()

        } catch AgentError.requiresApproval {
            logger.warning("Agent replacement requires user approval")
            agentInstalled = false
            servicesRunning = false
            agentResponding = false
            setAgentPermissionApprovalRequired(true)
            statusMessage = "Approval Required"
            agentInstaller.openSystemSettings()

        } catch {
            logger.error("Failed to restart agent: \(error.localizedDescription, privacy: .public)")
            servicesRunning = false
            agentResponding = false
            statusMessage = "Update failed"
        }
    }

    // MARK: - DNSSEC Control
    func setDNSSEC(enabled: Bool) {
        dnssecEnabled = enabled
        // The didSet saves the change through saveFullConfigToDaemon().
    }

    /// The fresh-install path shared by `enableDNS()` and the first-run trial
    /// step. A caller that arrives while a fresh install runs waits for it and
    /// sees the same error. A software update unregisters the Agent before the
    /// bundle is replaced, so no install starts while one is suspended, and the
    /// update waits for a running one. A stop, quit or Uninstall waits for a
    /// running install and then unregisters the Agent, so no install starts
    /// while one runs either.
    private func installAgent() async throws {
        if let agentInstallTask {
            return try await agentInstallTask.value
        }
        guard !softwareUpdateSuspended else { throw AgentError.softwareUpdateInProgress }
        guard !isStoppingDNS else { throw AgentError.servicesStopping }
        let task = Task { @MainActor in try await performAgentInstall() }
        agentInstallTask = task
        defer { agentInstallTask = nil }
        try await task.value
    }

    /// Every `AgentInstaller.install()` runs through here, so the fresh install,
    /// the restart of a dead Agent, the restore after a cancelled update and
    /// the Agent replacement never overlap.
    private func registerAgent() async throws {
        try await agentInstallSerializer.run { [self] in try await agentInstaller.install() }
    }

    private func performAgentInstall() async throws {
        statusMessage = "Installing agent..."
        try await registerAgent()
        agentInstalled = true
        setAgentPermissionApprovalRequired(false)

        // The new agent needs a fresh connection.
        XPCClient.shared.resetConnection()

        // Wait for agent to become ready (XPC listener registered)
        statusMessage = "Waiting for agent..."
        try await waitForAgentReady()
    }

    // MARK: - First Run

    /// Runs the trial step and hands over to `enableDNS()` unless the license
    /// blocks Enable, the app runs outside /Applications or the window was
    /// closed meanwhile. Returns true when it handed over.
    func turnOnFromFirstRun(windowOpen: @MainActor () -> Bool) async -> Bool {
        guard !firstRunPreparing else { return false }
        firstRunPreparing = true
        defer { firstRunPreparing = false }
        let startGeneration = dnsLifecycleGeneration

        let outcome = await makeFirstRunTrialStep(requestTrial: { [weak self] in
            guard let self else { return nil }
            return await storeFirstRunLicense(
                XPCClient.shared.validateLicenseAsync(),
                request: "trial request"
            )
        }).run()
        firstRunTrialStepFinished = true
        logger.info("First run Turn On: \(String(describing: outcome), privacy: .public)")

        guard
            FirstRunStepPolicy.handsOffToEnable(
                outcome,
                windowOpen: windowOpen(),
                startGeneration: startGeneration,
                currentGeneration: dnsLifecycleGeneration
            )
        else {
            if outcome == .licensed(blocksEnable: true) {
                licenseActivationFeedback = nil
                firstRunTrialEnded = true
            }
            updateStatusMessage()
            firstRunApprovedStep = nil
            return false
        }
        return startFreshInstallEnable()
    }

    /// Close and quit: requests the trial without waiting for the answer and
    /// leaves protection off. A step queued by a close that a removal
    /// overtook does nothing.
    func dismissFirstRun() async {
        guard !servicesRemovalRequested, !servicesRemoved else {
            logger.info("First run dismissed after services were removed, trial step skipped")
            return
        }
        let outcome = await makeFirstRunTrialStep(requestTrial: {
            XPCClient.shared.validateLicense { _ in }
            return nil
        }).run()
        firstRunTrialStepFinished = true
        logger.info("First run dismissed: \(String(describing: outcome), privacy: .public)")
        updateStatusMessage()
    }

    /// Activates a key from the Trial ended step and hands over to
    /// `enableDNS()` on success while the window is still open. On failure
    /// `licenseActivationFeedback` holds the reason. Returns true when it
    /// handed over.
    func activateLicenseAndTurnOn(key: String, windowOpen: @MainActor () -> Bool) async -> Bool {
        guard !firstRunPreparing else { return false }
        firstRunPreparing = true
        defer { firstRunPreparing = false }
        let startGeneration = dnsLifecycleGeneration

        guard await performLicenseActivation(key: key) else { return false }
        storeFirstRunLicense(
            await XPCClient.shared.getLicenseInfoAsync(),
            request: "license refresh after activation"
        )
        guard !LicenseEnableGatePolicy.blocksEnable(licenseInfo, agentInstalled: agentInstalled) else {
            logger.warning("First run activation succeeded but the known license still blocks Enable")
            firstRunTrialEnded = true
            return false
        }
        firstRunTrialEnded = false
        guard
            FirstRunStepPolicy.handsOffToEnable(
                .licensed(blocksEnable: false),
                windowOpen: windowOpen(),
                startGeneration: startGeneration,
                currentGeneration: dnsLifecycleGeneration
            )
        else {
            updateStatusMessage()
            return false
        }
        return startFreshInstallEnable()
    }

    /// Hands over to `enableDNS()` as a fresh install setup. Returns false when
    /// Enable refused to start, so the first-run window stays open.
    @discardableResult
    private func startFreshInstallEnable() -> Bool {
        guard enableDNS(asFreshInstallSetup: true) else {
            firstRunApprovedStep = nil
            return false
        }
        return true
    }

    /// The first-run window's "Try Again".
    func retryFreshInstallSetup() {
        startFreshInstallEnable()
    }

    /// The first-run window's "Continue" while a step waits for it.
    func continueFirstRunStep() {
        openFirstRunContinueGate()
    }

    /// The first-run window's "Skip" on the notifications step.
    func skipFirstRunNotifications() {
        firstRunNotificationsSkipped = true
        if firstRunAwaitingContinue == .notifications {
            openFirstRunContinueGate()
        }
        firstRunNotificationWait?.end()
    }

    /// Ends the open Continue gate and the notification wait without
    /// skipping, for a window close. Setup goes on without the window.
    func endFirstRunWaits() {
        openFirstRunContinueGate()
        firstRunNotificationWait?.end()
    }

    /// Holds the fresh install Enable before the macOS request of `step`
    /// until the window answers. An attempt superseded before the gate exists
    /// returns at once, because the lifecycle `didSet` had no gate to end.
    private func awaitFirstRunContinue(on step: FirstRunSetupStep, stepDone: Bool, generation: UInt64) async {
        guard persistedStateAvailability == .loaded, isCurrentDNSLifecycle(generation) else { return }
        guard
            FirstRunContinueGate.waits(
                stepDone: stepDone,
                windowOpen: firstRunWindowOpen,
                approved: firstRunApprovedStep == step
            )
        else { return }
        let gate = FirstRunContinueGate()
        firstRunContinueGate = gate
        firstRunAwaitingContinue = step
        logger.info("First run: waiting for Continue on \(String(describing: step), privacy: .public)")
        await gate.wait()
        if firstRunContinueGate === gate {
            firstRunContinueGate = nil
            firstRunAwaitingContinue = nil
        }
    }

    private func openFirstRunContinueGate() {
        firstRunContinueGate?.open()
        firstRunContinueGate = nil
        firstRunAwaitingContinue = nil
    }

    private func updateLateProviderRegistrationDeferral() {
        extensionManager.defersLateProviderRegistration = FreshInstallSetupPolicy.defersLateProviderRegistration(
            windowOpen: firstRunWindowOpen,
            setupGeneration: freshInstallSetupGeneration,
            currentGeneration: dnsLifecycleGeneration
        )
    }

    func refreshNotificationAuthorization() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        notificationsDecided = settings.authorizationStatus != .notDetermined
    }

    /// Asks for notifications and holds the setup until the user answers,
    /// skips or closes the window. Returns false when the request stays after
    /// protection starts. A superseded attempt neither waits nor asks.
    private func awaitFirstRunNotificationAnswer(generation: UInt64) async -> Bool {
        await refreshNotificationAuthorization()
        guard persistedStateAvailability == .loaded, isCurrentDNSLifecycle(generation) else { return true }
        switch FirstRunNotificationWait.request(
            notificationsDecided: notificationsDecided,
            skipped: firstRunNotificationsSkipped,
            windowOpen: firstRunWindowOpen
        ) {
        case .skipped:
            return true
        case .afterProtectionStarts:
            return false
        case .beforeResolver:
            break
        }
        let wait = FirstRunNotificationWait()
        firstRunNotificationWait = wait
        logger.info("First run: waiting for the notification answer")
        await wait.wait { [weak self] in
            guard let self, persistedStateAvailability == .loaded, isCurrentDNSLifecycle(generation) else { return }
            await requestNotificationAuthorization()
        }
        if firstRunNotificationWait === wait {
            firstRunNotificationWait = nil
        }
        await refreshNotificationAuthorization()
        return true
    }

    private func makeFirstRunTrialStep(
        requestTrial: @escaping () async -> LicenseInfo?
    ) -> FirstRunTrialStep {
        FirstRunTrialStep(
            isSupportedLocation: FirstRunStepPolicy.isSupportedInstallLocation(Bundle.main.bundleURL),
            agentInstalled: agentInstalled,
            installAgent: { [weak self] in try await self?.installAgent() },
            licenseInfo: { [weak self] in
                guard let self else { return nil }
                return await storeFirstRunLicense(
                    XPCClient.shared.getLicenseInfoAsync(),
                    request: "license lookup"
                )
            },
            requestTrial: requestTrial
        )
    }

    @discardableResult
    private func storeFirstRunLicense(
        _ result: Result<LicenseInfo, XPCError>,
        request: String
    ) -> LicenseInfo? {
        switch result {
        case .success(let info):
            licenseInfo = info
            return info
        case .failure(let error):
            logger.warning(
                "First run \(request, privacy: .public) failed: \(error.localizedDescription, privacy: .public)"
            )
            return nil
        }
    }

    // MARK: - Fresh Install Setup

    /// Runs when an Enable attempt ends. Only the current attempt of a fresh
    /// install reports. The happy path shows nothing, because macOS asks for its
    /// approvals and the app opens System Settings itself. A restart or a
    /// failure, which macOS does not explain, gets one alert.
    private func reportFreshInstallSetupOutcome(for lifecycleGeneration: UInt64) {
        guard
            FreshInstallSetupPolicy.reportsAttempt(
                setupGeneration: freshInstallSetupGeneration,
                attemptGeneration: lifecycleGeneration,
                currentGeneration: dnsLifecycleGeneration,
                isStopping: isStoppingDNS,
                updateSuspended: softwareUpdateSuspended
            )
        else {
            freshInstallSetupGeneration = FreshInstallSetupPolicy.setupGenerationAfterSupersededAttempt(
                lifecycleGeneration,
                setupGeneration: freshInstallSetupGeneration
            )
            return
        }
        let outcome = FreshInstallSetupPolicy(
            protectionActive: protectionDisplayState.isProtectionActive,
            restartRequired: extensionNotice == .restartRequired,
            approvalRequired: agentNeedsPermissionApproval || extensionManager.needsUserApproval,
            enableCompleted: isEnabled && runtimeDNSDesired
        ).outcome
        freshInstallSetupOutcome = outcome
        freshInstallSetupFailureMessage = outcome == .failed ? statusMessage : nil
        switch outcome {
        case .waitingForApproval:
            return
        case .done:
            freshInstallSetupGeneration = nil
        case .restartRequired:
            freshInstallSetupGeneration = nil
            logger.warning("Fresh install: restart required to finish setup")
            guard !firstRunWindowOpen else { return }
            FreshInstallSetupAlert.presentRestartRequired()
        case .failed:
            freshInstallSetupGeneration = nil
            logger.error("Fresh install: protection did not start: \(self.statusMessage, privacy: .public)")
            guard !firstRunWindowOpen else { return }
            FreshInstallSetupAlert.presentFailure(message: statusMessage) { [weak self] tryAgain in
                guard tryAgain, let self else { return }
                startFreshInstallEnable()
            }
        }
    }

    // MARK: - Proxy & Content Filter Control

    /// `setupGeneration` is the fresh install setup's attempt, whose DNS
    /// Proxy registration waits for Continue on "Allow DNS filtering".
    private func ensureDNSProxyConfigured(setupGeneration: UInt64? = nil) async throws {
        await extensionManager.updateStatus()

        if !extensionManager.isActive {
            logger.info("Activating extension...")
            try await extensionManager.activate(beforeRegistering: { [weak self] in
                guard let self, let setupGeneration else { return }
                await awaitFirstRunContinue(
                    on: .dnsFilter,
                    stepDone: extensionManager.isActive,
                    generation: setupGeneration
                )
                guard persistedStateAvailability == .loaded,
                    isCurrentDNSLifecycle(setupGeneration)
                else { throw CancellationError() }
            })
            await extensionManager.updateStatus()
        }

        extensionActive = extensionManager.isActive

        guard extensionManager.isActive else {
            throw ExtensionError.activationFailed("DNS Proxy did not become configured")
        }

        refreshPermissionApprovalState()
    }

    private func disableDNSProxyBeforeResolverStartIfNeeded() async throws {
        let startOrderPolicy = DNSProxyStartOrderPolicy(
            dnsProxyEnabledBeforeResolverStart: extensionManager.proxyEnabled
        )
        guard startOrderPolicy.shouldDisableProxyBeforeResolverStart else { return }

        try await extensionManager.disableProxy()
    }

    /// Enables the DNS Proxy, and the Content Filter when Block DoH & DoT is on.
    /// Use this instead of calling extensionManager.enableProxy() directly.
    private func ensureDNSProxyEnabled() async throws {
        try await ensureDNSProxyConfigured()

        if !extensionManager.proxyEnabled {
            try await extensionManager.enableProxy()
        }

        extensionActive = extensionManager.isActive

        guard extensionManager.proxyEnabled else {
            throw ExtensionError.activationFailed("DNS Proxy did not become enabled")
        }

        refreshPermissionApprovalState()
    }

    @discardableResult
    private func enableProxyAndContentFilter(
        for lifecycleGeneration: UInt64,
        expectedWakeGeneration: UInt64? = nil,
        enableContentFilterAfterProxy: Bool = true
    ) async -> ProxyEnableResult {
        guard isCurrentDNSLifecycle(lifecycleGeneration),
            isCurrentServiceWake(expectedWakeGeneration)
        else { return .inactive }

        guard !captivePortalDetected else {
            logger.info("Skipping proxy enable while captive portal bypass is active")
            return .captivePortalBypass
        }

        // Capture the Agent's generation before the await so a resolver
        // stop/start during activation can be detected afterwards.
        let preEnableRuntimeState: AgentRuntimeState?
        if case .success(let preState) = await XPCClient.shared.getRuntimeStateAsync() {
            preEnableRuntimeState = preState
        } else {
            preEnableRuntimeState = nil
        }

        guard
            ProxyEnableRuntimeValidationPolicy.canStartProxyEnable(
                preEnableRuntimeState: preEnableRuntimeState,
                appLifecycleIsCurrent: isCurrentDNSLifecycle(lifecycleGeneration)
                    && isCurrentServiceWake(expectedWakeGeneration),
                runtimeDNSDesired: runtimeDNSDesired,
                isStopping: isStoppingDNS
            ),
            let expectedAgentGeneration = preEnableRuntimeState?.lifecycleGeneration
        else {
            logger.warning("Skipping proxy enable without healthy authoritative runtime state")
            scheduleServiceStateReconciliation(reason: "proxy-enable-admission")
            return .inactive
        }

        do {
            try await ensureDNSProxyEnabled()
            guard isCurrentDNSLifecycle(lifecycleGeneration) else {
                await rollbackStaleProxyEnableIfNeeded(from: lifecycleGeneration)
                return .inactive
            }
            guard isCurrentServiceWake(expectedWakeGeneration) else { return .inactive }

            if await disableProxyIfCaptivePortalBypassBecameActive() {
                return .captivePortalBypass
            }

            guard
                await proxyEnableSurvivesRuntimeRevalidation(
                    lifecycleGeneration: lifecycleGeneration,
                    expectedWakeGeneration: expectedWakeGeneration,
                    expectedAgentGeneration: expectedAgentGeneration
                )
            else {
                guard isCurrentServiceWake(expectedWakeGeneration) else { return .inactive }
                await rollbackRejectedProxyEnable(from: lifecycleGeneration)
                scheduleServiceStateReconciliation(reason: "proxy-enable-revalidation")
                return .inactive
            }

            if enableContentFilterAfterProxy {
                enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
            }
            return .enabled
        } catch {
            guard isCurrentDNSLifecycle(lifecycleGeneration) else {
                await rollbackStaleProxyEnableIfNeeded(from: lifecycleGeneration)
                return .inactive
            }
            guard isCurrentServiceWake(expectedWakeGeneration) else { return .inactive }
            // An enable deferred by a replacement drain is not a failure. The
            // drain replays it once the extension swap completes.
            if !extensionManager.isReplacementDrainActive {
                logger.error("Failed to enable proxy: \(error.localizedDescription, privacy: .public)")
            }
            refreshPermissionApprovalState()
            if case ExtensionError.activationRequiresReboot = error {
                setExtensionNotice(.restartRequired)
            } else if extensionManager.needsUserApproval {
                resumeDNSAfterProxyApproval = true
            }
            return .inactive
        }
    }

    /// Revalidates the Agent's runtime state after the proxy activation await.
    ///
    /// Returns false when the Agent restarted, is transitioning, stopped the
    /// resolver, entered captive bypass, or its state cannot be read.
    private func proxyEnableSurvivesRuntimeRevalidation(
        lifecycleGeneration: UInt64,
        expectedWakeGeneration: UInt64?,
        expectedAgentGeneration: UInt64
    ) async -> Bool {
        var postState: AgentRuntimeState?
        if case .success(let state) = await XPCClient.shared.getRuntimeStateAsync() {
            postState = state
        }

        return ProxyEnableRuntimeValidationPolicy.shouldKeepProxyEnabled(
            postEnableRuntimeState: postState,
            expectedAgentLifecycleGeneration: expectedAgentGeneration,
            appLifecycleIsCurrent: isCurrentDNSLifecycle(lifecycleGeneration)
                && isCurrentServiceWake(expectedWakeGeneration),
            runtimeDNSDesired: runtimeDNSDesired,
            isStopping: isStoppingDNS
        )
    }

    private func disableProxyIfCaptivePortalBypassBecameActive() async -> Bool {
        guard captivePortalDetected else { return false }

        cancelPendingContentFilterEnable(clearNotice: false)

        if extensionManager.proxyEnabled {
            do {
                try await extensionManager.disableProxy()
            } catch {
                logger.error(
                    "Failed to disable proxy for captive portal bypass: \(error.localizedDescription, privacy: .public)"
                )
            }
        }

        applyRuntimeStatePresentation(
            RuntimeStatePresentation(
                providerState: .unknown,
                forwarding: false,
                resolverMode: ProtectionStatusPolicy.captiveBypassMessage
            )
        )
        updateStatusMessage()
        return true
    }

    /// Coalesces concurrent enable requests. `FilterManager` serializes the
    /// underlying preference transaction with disable and removal requests.
    private func enableContentFilterInBackgroundIfNeeded(reason: String) {
        guard blockDohDotEnabled, runtimeDNSDesired, !isStoppingDNS else { return }
        guard contentFilterEnableTask == nil else { return }

        if filterManager.filterEnabled {
            clearExtensionNoticeIfResolved()
            return
        }

        contentFilterEnableGeneration += 1
        let generation = contentFilterEnableGeneration

        contentFilterEnableTask = Task { @MainActor [weak self] in
            guard let self = self else { return }
            defer {
                if self.contentFilterEnableGeneration == generation {
                    self.contentFilterEnableTask = nil
                }
            }

            do {
                try Task.checkCancellation()
                guard self.shouldKeepContentFilterEnabled else { return }

                try await self.extensionManager.enableContentFilter()

                try Task.checkCancellation()
                if !self.shouldKeepContentFilterEnabled {
                    try await self.extensionManager.disableContentFilter()
                    return
                }

                self.logger.info("Content Filter enabled (\(reason, privacy: .public))")
                self.clearExtensionNoticeIfResolved()
            } catch is CancellationError {
                await self.disableContentFilterAfterCancelledEnableIfNeeded()
            } catch {
                guard self.contentFilterEnableGeneration == generation,
                    self.shouldKeepContentFilterEnabled
                else { return }
                self.handleContentFilterEnableFailure(error)
            }
        }
    }

    private func cancelPendingContentFilterEnable(clearNotice: Bool = true) {
        contentFilterEnableGeneration += 1
        contentFilterEnableTask?.cancel()
        contentFilterEnableTask = nil

        if clearNotice && extensionNotice != .none {
            setExtensionNotice(.none)
        }
    }

    private func disableContentFilterAfterCancelledEnableIfNeeded() async {
        guard !shouldKeepContentFilterEnabled else { return }

        do {
            try await extensionManager.disableContentFilter()
            logger.info("Content Filter disabled after cancelled enable")
        } catch {
            logger.warning(
                "Failed to disable Content Filter after cancelled enable: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    private func disableContentFilterIfNotNeeded() async {
        guard shouldDisableContentFilter else { return }

        do {
            try await extensionManager.disableContentFilter()
            logger.info("Content Filter disabled because DNS protection is inactive")
            clearExtensionNoticeIfResolved()
        } catch {
            logger.warning(
                "Failed to disable Content Filter while DNS protection is inactive: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    private func disableContentFilterForStopIfNeeded() async -> Bool {
        do {
            let contentFilterEnabled = try await filterManager.refreshStatus()
            let stopPolicy = DNSStopFlowPolicy(contentFilterEnabled: contentFilterEnabled)
            guard stopPolicy.shouldDisableContentFilter else { return true }

            try await extensionManager.disableContentFilter()
            let contentFilterStillEnabled = try await filterManager.refreshStatus()
            guard !contentFilterStillEnabled else {
                logger.error("Content Filter remained enabled after disable request")
                statusMessage = "Failed to disable Content Filter"
                return false
            }
            logger.info("Content Filter disabled during DNS stop")
            clearExtensionNoticeIfResolved()
            return true
        } catch {
            logger.warning(
                "Failed to disable Content Filter during DNS stop: \(error.localizedDescription, privacy: .public)"
            )
            statusMessage = "Failed to disable Content Filter"
            return false
        }
    }

    private func isCurrentDNSLifecycle(_ generation: UInt64) -> Bool {
        runtimeDNSDesired && !isStoppingDNS && !softwareUpdateSuspended && dnsLifecycleGeneration == generation
    }

    private func isCurrentServiceWake(_ expectedGeneration: UInt64?) -> Bool {
        guard let expectedGeneration else { return true }
        return serviceWakeupGate.currentGeneration == expectedGeneration
    }

    private func rollbackStaleProxyEnableIfNeeded(from staleGeneration: UInt64) async {
        let cleanupGeneration = dnsLifecycleGeneration
        guard staleGeneration != cleanupGeneration,
            !runtimeDNSDesired,
            !isStoppingUnexpectedResolver
        else { return }

        _ = await disableProxyForStoppedLifecycle(
            expectedGeneration: cleanupGeneration
        )
    }

    private func rollbackRejectedProxyEnable(from attemptGeneration: UInt64) async {
        guard
            ProxyEnableRuntimeValidationPolicy.shouldRollbackRejectedEnable(
                attemptLifecycleGeneration: attemptGeneration,
                currentLifecycleGeneration: dnsLifecycleGeneration
            )
        else { return }

        await disableDNSProxyAfterServiceStop()

        let currentGeneration = dnsLifecycleGeneration
        guard currentGeneration != attemptGeneration,
            servicesRunning,
            isCurrentDNSLifecycle(currentGeneration)
        else { return }
        _ = await enableProxyAndContentFilter(for: currentGeneration)
    }

    private func stopServicesAfterStaleStart(
        from staleGeneration: UInt64,
        stopWhenPersistedStateUnavailable: Bool = false
    ) async {
        let cleanupGeneration = dnsLifecycleGeneration
        if stopWhenPersistedStateUnavailable,
            persistedStateAvailability != .loaded,
            staleGeneration == cleanupGeneration
        {
            let outcome = await stopServicesInOrder { [weak self] in
                guard let self else { return false }
                return await self.stopAgentResolverForCleanup()
            }
            if outcome.agentStopped {
                servicesRunning = false
            }
            return
        }

        guard staleGeneration != cleanupGeneration,
            !runtimeDNSDesired,
            !isStoppingUnexpectedResolver
        else { return }

        _ = await AppServiceStopOrderPolicy.execute { [weak self] step in
            guard let self else { return false }
            switch step {
            case .stopAgentServices:
                guard self.dnsLifecycleGeneration == cleanupGeneration,
                    !self.runtimeDNSDesired,
                    !self.isStoppingDNS,
                    !self.isStoppingUnexpectedResolver
                else { return false }
                return await self.stopAgentResolverForCleanup()
            case .disableDNSProxy:
                return await self.disableProxyForStoppedLifecycle(
                    expectedGeneration: cleanupGeneration
                )
            }
        }
    }

    private func disableProxyForStoppedLifecycle(
        expectedGeneration: UInt64
    ) async -> Bool {
        guard dnsLifecycleGeneration == expectedGeneration, !runtimeDNSDesired else {
            return false
        }
        let proxyDisabled = await disableDNSProxyAfterServiceStop()

        let currentGeneration = dnsLifecycleGeneration
        guard currentGeneration != expectedGeneration || runtimeDNSDesired else {
            return proxyDisabled
        }
        guard servicesRunning, isCurrentDNSLifecycle(currentGeneration) else {
            return proxyDisabled
        }
        _ = await enableProxyAndContentFilter(for: currentGeneration)
        return proxyDisabled
    }

    private func stopResolverStartedWithoutEnabledPreference() {
        guard persistedStateAvailability.allowsLifecycleActions,
            !isStoppingDNS,
            !isStoppingUnexpectedResolver
        else { return }
        proxyControlBounceTask?.cancel()
        dnsLifecycleGeneration &+= 1
        runtimeDNSDesired = false
        isStoppingUnexpectedResolver = true

        Task { @MainActor [self] in
            defer { isStoppingUnexpectedResolver = false }
            _ = await stopServicesInOrder { [weak self] in
                guard let self else { return false }
                return await self.stopAgentResolverForCleanup()
            }
            servicesRunning = false
            updateStatusMessage()
        }
    }

    private func handleContentFilterEnableFailure(_ error: Error) {
        logger.warning("Failed to enable Content Filter: \(error.localizedDescription, privacy: .public)")
        refreshPermissionApprovalState()

        if case FilterError.activationRequiresReboot = error {
            setExtensionNotice(.restartRequired)
        } else if anyExtensionNeedsUserApproval {
            setExtensionNotice(.filterApprovalRequired)
        }
    }

    private func clearExtensionNoticeIfResolved() {
        refreshPermissionApprovalState()
        extensionNotice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: extensionManager.activationRequiresRestart,
            filterRequiresRestart: filterManager.activationRequiresRestart,
            versionStale: extensionVersionStale,
            recoveryExhausted: proxyControlRecoveryExhausted
                || extensionManager.replacementDrainUnconfirmed
        )
        extensionNotice.applyApprovalStatus(
            proxyNeedsApproval: extensionManager.needsUserApproval,
            filterNeedsApproval: filterManager.needsUserApproval
        )
        updateStatusMessage()
    }

    private func setExtensionNotice(_ notice: ExtensionNotice) {
        extensionNotice = notice
        if notice == .restartRequired {
            sendNotificationOnce(
                id: "extension-restart-required",
                title: "Restart Required",
                body: "Restart your Mac to finish updating MacDNS protection.")
        }
        updateStatusMessage()
    }

    private func disableDNSProxyForStop() async -> Bool {
        do {
            try await extensionManager.disableProxy()
            extensionActive = false
            return true
        } catch {
            logger.warning("Failed to disable proxy: \(error.localizedDescription, privacy: .public)")
            statusMessage = "Failed to disable DNS Proxy"
            return false
        }
    }

    @discardableResult
    private func disableDNSProxyAfterServiceStop() async -> Bool {
        do {
            try await extensionManager.disableProxy()
            return true
        } catch {
            logger.error("Failed to disable proxy: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Every App-side cleanup path shares this order: stop the Agent, then
    /// reconcile the DNS Proxy manager to disabled.
    private func stopServicesInOrder(
        stopAgentServices: @escaping () async -> Bool
    ) async -> AppServiceStopOutcome {
        await AppServiceStopOrderPolicy.execute { step in
            switch step {
            case .stopAgentServices:
                return await stopAgentServices()
            case .disableDNSProxy:
                return await self.disableDNSProxyAfterServiceStop()
            }
        }
    }

    private func stopAgentResolverForCleanup() async -> Bool {
        if case .success(true) =
            await XPCClient.shared.stopResolverAsync(force: false)
        {
            return true
        }
        return false
    }

    // MARK: - DoH/DoT Block Control

    /// Applies the runtime side effect the Block DoH & DoT toggle decided on.
    /// The suppression decision belongs to the property observer, not here.
    private func applyBlockDohDotSideEffect(
        _ sideEffect: BlockDohDotSideEffect
    ) async {
        switch sideEffect {
        case .none:
            return

        case .enableContentFilter:
            if extensionManager.proxyEnabled {
                enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
            }

        case .disableContentFilter:
            guard !shouldKeepContentFilterEnabled else {
                enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                return
            }
            cancelPendingContentFilterEnable()

            do {
                try await extensionManager.disableContentFilter()
                guard !shouldKeepContentFilterEnabled else {
                    enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                    return
                }
                logger.info("Content Filter disabled (Block DoH & DoT)")
            } catch {
                guard !shouldKeepContentFilterEnabled else {
                    enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                    return
                }
                logger.error("Failed to disable Content Filter: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: - Captive Portal Status
    func updateCaptivePortalStatus() {
        XPCClient.shared.getCaptivePortalStatus { [weak self] _, resolverMode in
            DispatchQueue.main.async {
                guard let self = self else { return }

                // The detector status only reports a suspicion raised by an
                // unauthenticated HTTP probe. The agent's resolver mode is the
                // authoritative report of whether a full bypass is active.
                if let mode = resolverMode {
                    self.captivePortalDetected = (mode == "bypass")
                    if mode == "normal" {
                        self.resolverMode = ProtectionStatusPolicy.encryptedModeMessage
                    } else if mode == "forwarding" {
                        self.resolverMode = ProtectionStatusPolicy.forwardingModeMessage
                    } else if mode == "bypass" {
                        self.resolverMode = ProtectionStatusPolicy.captiveBypassMessage
                    }
                }
            }
        }
    }

    func recheckCaptivePortal() {
        XPCClient.shared.recheckCaptivePortal { [weak self] success in
            guard let self = self else { return }
            if !success {
                self.logger.warning("Captive portal recheck failed")
            }
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 2_000_000_000)  // 2 seconds
                self?.updateCaptivePortalStatus()
            }
        }
    }

    /// Grants the agent's full-bypass approval for the attached network. This is
    /// the only writer: a probe result can neither create nor renew it.
    ///
    /// The agent applies the grant to a portal it already suspects, so this only
    /// has to refresh what the UI displays. A recheck cannot do it: the detector
    /// reports status changes, and a portal that keeps confirming `.captive`
    /// produces none.
    func approveCaptivePortalBypass() {
        XPCClient.shared.approveCaptivePortalBypass { [weak self] approved in
            guard let self = self else { return }
            guard approved else {
                self.logger.warning("Captive portal bypass approval refused by the agent")
                return
            }
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                self?.updateCaptivePortalStatus()
            }
        }
    }

    // MARK: - Blocklist Management

    private func loadBlocklistSettings() {
        blocklistSettingsLoadGeneration &+= 1
        let generation = blocklistSettingsLoadGeneration
        isLoadingBlocklist = true

        XPCClient.shared.getBlocklistSettings { [weak self] settings in
            DispatchQueue.main.async {
                guard let self = self, self.blocklistSettingsLoadGeneration == generation else { return }

                defer { self.isLoadingBlocklist = false }

                let resolution = BlocklistSettingsLoadResolution.resolve(
                    agentSettings: settings,
                    fileSettings: { self.loadBlocklistSettingsFromFile() }
                )

                guard case .apply(let settings) = resolution else {
                    self.logger.warning("Failed to load blocklist settings from agent and file")
                    return
                }

                self.blocklistSettings = settings
                self.blocklistEnabled = settings.enabled
                self.blocklistSettingsLoaded = true
                self.blocklistSettingsVersion += 1
            }
        }
    }

    private func saveBlocklistSettings() {
        guard blocklistSettingsLoaded && !isLoading && !isLoadingBlocklist else { return }

        blocklistSettings.enabled = blocklistEnabled
        XPCClient.shared.saveBlocklistSettings(
            settings: blocklistSettings,
            onLateReply: { [weak self] _ in self?.loadBlocklistSettings() },
            completion: { [weak self] result in
                guard let self = self else { return }
                if result.shouldFallbackToFile(agentAllowsFallback: self.agentInstaller.canUseStateFileFallback()) {
                    self.logger.warning("XPC save blocklist failed, falling back to file save")
                    self.saveBlocklistSettingsToFile()
                } else if result == .agentUnavailable || result == .timedOut {
                    self.statusMessage = "Blocklist changes could not be confirmed."
                    self.loadBlocklistSettings()
                } else if result == .rejectedByAgent {
                    self.logger.warning("Agent rejected blocklist settings; reloading rollback from agent")
                    self.loadBlocklistSettings()
                } else if result == .encodingFailed {
                    self.logger.error("Failed to encode blocklist settings; not saving fallback")
                }
            }
        )
    }

    /// Saves blocklist settings to `state.json` (fallback when the agent is not
    /// responding). The write is the same revision-guarded compare-and-swap the
    /// rest of the configuration uses, so a stale App loses instead of
    /// overwriting a newer document. The derived `blocklist_settings.json`
    /// projection stays agent-owned and is re-emitted when the agent returns.
    private func saveBlocklistSettingsToFile() {
        let snapshot = BlocklistSettingsTransactionPolicy.config(
            buildFullConfigSnapshot(),
            settings: blocklistSettings
        )
        guard
            let persistedRevision = saveStateToFile(
                snapshot,
                expectedRevision: fullConfigSaveCoordinator.revision
            )
        else {
            logger.error("Fallback blocklist save rejected; reloading settings")
            loadBlocklistSettings()
            return
        }
        fullConfigSaveCoordinator.adoptRevision(
            from: ["configRevision": persistedRevision]
        )
        logger.info("Blocklist settings saved to state.json (fallback)")
    }

    func forceBlocklistUpdate() {
        guard !isUpdatingBlocklist else { return }
        isUpdatingBlocklist = true
        XPCClient.shared.forceBlocklistUpdate { [weak self] success in
            DispatchQueue.main.async {
                self?.isUpdatingBlocklist = false
                if success {
                    // Reload settings to get updated timestamps
                    self?.loadBlocklistSettings()
                }
            }
        }
    }

    // Called from the UI's onAppear.
    func refreshBlocklistSettings() {
        loadBlocklistSettings()
    }

    func getCategoryLevel(_ category: BlocklistCategory) -> CategoryLevel {
        return blocklistSettings.level(for: category)
    }

    func setCategoryLevel(_ category: BlocklistCategory, level: CategoryLevel) {
        guard !isLoadingBlocklist else { return }

        blocklistSettings.setLevel(level, for: category)
        blocklistSettingsVersion += 1
        saveBlocklistSettings()
    }

    var blocklistLastUpdated: Date? {
        return blocklistSettings.lastUpdated
    }

    // MARK: - Cache Management

    func flushDNSCache(completion: @escaping (Bool) -> Void) {
        XPCClient.shared.flushCache { success in
            completion(success)
        }
    }

    // MARK: - Blocklist Statistics

    func loadBlocklistStats() {
        Task { [weak self] in
            await self?.refreshBlocklistStats(isAutomatic: false)
        }
    }

    func refreshBlocklistStats(isAutomatic: Bool) async {
        guard let generation = activityStatsRefresh.begin(isAutomatic: isAutomatic) else { return }
        if isLoadingStats != activityStatsRefresh.isLoading {
            isLoadingStats = activityStatsRefresh.isLoading
        }
        let range = activityRange
        let result = await XPCClient.shared.queryHistory(
            QueryHistoryRequest(.topBlocked(range: .last(range), category: nil, limit: 100)),
            as: QueryHistoryTopBlocked.self
        )
        // A range switch starts a newer load, and an older answer must not replace it.
        let load = QueryHistoryLoad(result).map(\.blockedDomains)
        let domainsChanged = activityStatsRefresh.finish(load, for: generation)
        if domainsChanged {
            blocklistStats = activityStatsRefresh.domains
        }
        if blocklistStatsIssue != activityStatsRefresh.issue {
            blocklistStatsIssue = activityStatsRefresh.issue
        }
        if isLoadingStats != activityStatsRefresh.isLoading {
            isLoadingStats = activityStatsRefresh.isLoading
        }
    }

    // MARK: - Lookup History

    func setQueryHistoryRetentionDays(_ days: Int) {
        queryHistorySettings = queryHistorySettings.withRetentionDays(days)
    }

    func loadQueryHistoryStatus() {
        Task { [weak self] in
            let result = await XPCClient.shared.queryHistory(
                QueryHistoryRequest(.status),
                as: QueryHistoryStatus.self
            )
            self?.queryHistoryStatus = QueryHistoryLoad(result)
        }
    }

    /// Deletes every stored lookup. Pages watch `queryHistoryClear.finishedCount`
    /// to reload, and show `failureMessage` when the agent did not confirm.
    func clearQueryHistory() {
        guard queryHistoryClear.begin() else { return }
        Task { [weak self] in
            let result = await XPCClient.shared.clearQueryHistory()
            guard let self else { return }
            if case .success(true) = result {
                self.logger.info("Lookup history cleared")
            } else {
                self.logger.error("Lookup history clear failed")
            }
            self.queryHistoryClear.finish(result)
        }
    }

    func dismissQueryHistoryClearFailure() {
        queryHistoryClear.dismissFailure()
    }

    // MARK: - Local Record Shortcuts

    @discardableResult
    func blockWithLocalRecords(host: String) -> Bool {
        guard let blocked = LocalRecordShortcut.blocking(host, in: dnsOverrides) else { return false }
        return ConfigurationMutationBoundary.performIfAllowed(availability: persistedStateAvailability) {
            dnsOverrides = blocked
        }
    }

    @discardableResult
    func unblockLocalRecords(host: String) -> Bool {
        ConfigurationMutationBoundary.performIfAllowed(availability: persistedStateAvailability) {
            dnsOverrides = LocalRecordShortcut.unblocking(host, in: dnsOverrides)
        }
    }

    @discardableResult
    func addLocalRecord(host: String, qtype: String, value: String) -> Bool {
        guard let added = LocalRecordShortcut.adding(host: host, qtype: qtype, value: value, to: dnsOverrides) else {
            return false
        }
        return ConfigurationMutationBoundary.performIfAllowed(availability: persistedStateAvailability) {
            dnsOverrides = added
        }
    }

    // MARK: - Allowlist Management

    @discardableResult
    func addToAllowlist(domain: String) -> Bool {
        ConfigurationMutationBoundary.performIfAllowed(
            availability: persistedStateAvailability
        ) {
            let newDomain = AllowedDomain(domain: domain, enabled: true)
            allowedDomains.append(newDomain)
            saveFullConfigToDaemon()
        }
    }

    func removeFromAllowlist(id: UUID) {
        allowedDomains.removeAll { $0.id == id }
        saveFullConfigToDaemon()
    }

    func toggleAllowlistDomain(id: UUID) {
        guard let index = allowedDomains.firstIndex(where: { $0.id == id }) else { return }
        allowedDomains[index].enabled.toggle()
        saveFullConfigToDaemon()
    }

    func refreshAllowlist() {
        guard !isLoadingAllowlist else { return }
        let mutationGenerationAtStart = persistedStateMutationGeneration
        isLoadingAllowlist = true

        XPCClient.shared.getFullConfig { [weak self] config in
            DispatchQueue.main.async {
                guard let self = self else { return }
                defer { self.isLoadingAllowlist = false }
                guard
                    PersistedStateResponsePolicy.canApply(
                        requestGeneration: mutationGenerationAtStart,
                        currentGeneration: self.persistedStateMutationGeneration,
                        coordinatorIsIdle: self.fullConfigSaveCoordinator.isIdle
                    )
                else {
                    self.logger.info(
                        "Ignoring stale allowlist refresh after a newer local change"
                    )
                    return
                }

                let finalConfig: [String: Any]?
                if let config = config {
                    finalConfig = config
                } else if self.agentInstaller.canUseStateFileFallback() {
                    finalConfig = self.loadStateFromFile()
                } else {
                    finalConfig = nil
                }

                guard let config = finalConfig,
                    let allowlistData = config["allowlist"] as? [[String: Any]]
                else { return }

                self.allowedDomains = AllowedDomain.parseArray(allowlistData)
            }
        }
    }

    // MARK: - License Management

    func loadLicenseInfo() {
        guard !isLoadingLicense else { return }

        isLoadingLicense = true
        let capturedWakeGeneration = licenseStatusWakeupGate.currentGeneration

        Task { @MainActor [weak self] in
            guard let self else { return }
            defer { isLoadingLicense = false }

            let result = await XPCClient.shared.getLicenseInfoAsync()
            guard
                capturedWakeGeneration
                    == licenseStatusWakeupGate.currentGeneration
            else { return }

            switch result {
            case .success(let info):
                licenseInfo = info
                agentResponding = true

            case .failure(let error):
                agentResponding = false
                let canUseFileFallback = agentInstaller.canUseStateFileFallback()
                licenseInfo = LicenseInfoLoadFailurePolicy.resolve(
                    lastAuthoritativeInfo: licenseInfo,
                    canUseFileFallback: canUseFileFallback
                ) {
                    self.loadLicenseFromFile()
                }
                logger.warning(
                    "License info load failed: \(error.localizedDescription, privacy: .public)"
                )
            }

            updateStatusMessage()
        }
    }

    // MARK: - Update Info

    /// Reads the Agent cache, including updates detected before the App started observing.
    func loadUpdateInfo(presentIfAvailable: Bool = false) {
        updateInfoLoader.refresh(presentIfAvailable: presentIfAvailable)
    }

    /// Reads license state directly only when the Agent cannot execute.
    private func loadLicenseFromFile() -> LicenseInfo? {
        let outcome = LicenseInfoFileFallback(
            path: PathResolver.licenseFile
        ).load()
        if let failureDescription = outcome.failureDescription {
            logger.error(
                "License file fallback is fail-closed: \(failureDescription, privacy: .public)"
            )
        }
        return outcome.info
    }

    // MARK: - Scheduled Notifications

    /// Schedules the license and trial expiration notifications. Runs whenever
    /// licenseInfo is updated.
    private func scheduleExpirationNotifications() {
        let plan = LicenseExpirationNotificationPlan.make(for: licenseInfo)
        UNUserNotificationCenter.current().removePendingNotificationRequests(
            withIdentifiers: plan.identifiersToRemove
        )

        guard let expiresAt = licenseInfo?.expiresAt else { return }
        let typeLabel = licenseInfo?.status == .trial ? "trial" : "license"
        logger.info(
            "Scheduling \(typeLabel, privacy: .public) expiration notifications (expires: \(expiresAt.formatted(date: .abbreviated, time: .shortened), privacy: .public))"
        )

        for notification in plan.notifications {
            scheduleNotification(
                id: notification.id,
                title: notification.title,
                body: notification.body,
                timeInterval: notification.timeInterval
            )
        }
    }

    private func scheduleNotification(id: String, title: String, body: String, timeInterval: TimeInterval) {
        let center = UNUserNotificationCenter.current()

        center.getNotificationSettings { [weak self] settings in
            guard settings.authorizationStatus == .authorized else {
                self?.logger.warning("Notification permission not granted, cannot schedule \(id, privacy: .public)")
                return
            }

            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            content.interruptionLevel = .timeSensitive

            let trigger = UNTimeIntervalNotificationTrigger(timeInterval: timeInterval, repeats: false)
            let request = UNNotificationRequest(identifier: id, content: content, trigger: trigger)

            center.add(request) { error in
                if let error = error {
                    self?.logger.error(
                        "Failed to schedule '\(id, privacy: .public)': \(error.localizedDescription, privacy: .public)"
                    )
                } else {
                    let fireDate = Date().addingTimeInterval(timeInterval)
                    let hours = Int(timeInterval / 3600)
                    let minutes = Int((timeInterval.truncatingRemainder(dividingBy: 3600)) / 60)
                    let fireDateLabel = fireDate.formatted(date: .abbreviated, time: .shortened)
                    let scheduledMessage =
                        "Scheduled '\(id)' for \(fireDateLabel) (\(hours)h \(minutes)m)"
                    self?.logger.info("\(scheduledMessage, privacy: .public)")
                }
            }
        }
    }

    // MARK: - Immediate Notifications

    /// Sends an immediate notification with a 24-hour cooldown per ID.
    private func sendNotificationOnce(id: String, title: String, body: String) {
        let key = "lastNotification_\(id)"
        let lastNotification = UserDefaults.standard.object(forKey: key) as? Date
        let cooldown: TimeInterval = 24 * 3600

        if let last = lastNotification, Date().timeIntervalSince(last) < cooldown {
            logger.debug("Notification \(id, privacy: .public) skipped - cooldown active")
            return
        }

        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { [weak self] settings in
            guard settings.authorizationStatus == .authorized else {
                self?.logger.warning("Notification permission not granted")
                return
            }

            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            content.interruptionLevel = .timeSensitive

            let request = UNNotificationRequest(
                identifier: id,
                content: content,
                trigger: nil  // Immediate
            )

            center.add(request) { error in
                if let error = error {
                    self?.logger.error(
                        "Failed to send notification: \(error.localizedDescription, privacy: .public)"
                    )
                } else {
                    self?.logger.info("Sent notification: \(id, privacy: .public)")
                    UserDefaults.standard.set(Date(), forKey: key)
                }
            }
        }
    }

    func requestNotificationPermission() {
        Task { await requestNotificationAuthorization() }
    }

    private func requestNotificationAuthorization() async {
        do {
            let granted = try await UNUserNotificationCenter.current().requestAuthorization(
                options: [.alert, .sound])
            if granted {
                logger.info("Notification permission granted")
                // Reminders for a license that arrived before the grant were skipped.
                scheduleExpirationNotifications()
            } else {
                logger.warning("Notification permission denied")
            }
        } catch {
            logger.error(
                "Failed to request notification permission: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// Reads state.json directly when the agent service cannot execute.
    private func loadPersistedStateFromFile() -> PersistedStateFileLoadOutcome {
        switch StateFileLock.load(stateFile: PathResolver.stateFile) {
        case .missing:
            return .missing
        case .valid(let config):
            guard
                let validated = DNSPolicyStructuralPolicy.validateAndNormalize(config)
            else {
                logger.error(
                    "Failed to read state file: malformed customZones or dnsOverrides"
                )
                return .invalidConfiguration
            }
            return .valid(validated.normalizedConfig)
        case .invalid(let reason):
            logger.error("Failed to read state file: \(reason, privacy: .public)")
            return .invalidConfiguration
        case .ioFailure(let reason):
            logger.error("Failed to read state file: \(reason, privacy: .public)")
            return .ioFailure
        }
    }

    private func loadStateFromFile() -> [String: Any]? {
        guard case .valid(let config) = loadPersistedStateFromFile() else {
            return nil
        }
        // Blocklist settings are agent-owned and reach the App over their own
        // XPC calls, so they stay out of the payload compared against the
        // authoritative document.
        return BlocklistSettingsTransactionPolicy.configWithoutSettings(config)
    }

    /// Reads blocklist settings from `state.json` (fallback when the agent is
    /// not responding).
    private func loadBlocklistSettingsFromFile() -> BlocklistSettings? {
        guard case .valid(let config) = loadPersistedStateFromFile() else {
            return nil
        }
        switch BlocklistSettingsTransactionPolicy.persisted(
            in: config,
            dbBasePath: PathResolver.blocklistsDir.path
        ) {
        case .valid(let settings):
            return settings
        case .missing:
            return nil
        case .malformed:
            logger.error("Blocklist settings in state.json are malformed")
            return nil
        }
    }

    func activateLicense(key: String) {
        guard !isLoadingLicense else { return }

        Task { @MainActor [weak self] in
            guard let self, await performLicenseActivation(key: key) else { return }
            loadLicenseInfo()
        }
    }

    /// Publishes `licenseActivationFeedback` and returns true when the key is
    /// active on this machine. A timeout reloads the license, because the agent
    /// may still finish the activation.
    private func performLicenseActivation(key: String) async -> Bool {
        guard !isLoadingLicense else { return false }
        licenseActivationFeedback = nil

        let outcome: Result<LicenseActivationResult, XPCError>
        do {
            isLoadingLicense = true
            defer { isLoadingLicense = false }
            outcome = await XPCClient.shared.activateLicenseAsync(licenseKey: key)
        }

        licenseActivationFeedback = LicenseActivationFeedback(outcome: outcome)
        switch outcome {
        case .success(.success), .success(.alreadyActivated):
            return true
        case .failure(.timeout):
            loadLicenseInfo()
            return false
        default:
            return false
        }
    }

    func refreshLicenseStatus() {
        guard !isLoadingLicense else { return }

        isLoadingLicense = true

        let timeoutWorkItem = DispatchWorkItem { [weak self] in
            guard let self = self, self.isLoadingLicense else { return }
            self.logger.warning("License refresh timeout - resetting state")
            self.isLoadingLicense = false
            self.updateStatusMessage()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0, execute: timeoutWorkItem)

        XPCClient.shared.validateLicense { [weak self] info in
            timeoutWorkItem.cancel()

            DispatchQueue.main.async {
                guard let self = self else { return }
                self.licenseInfo = LicenseInfoLoadFailurePolicy.resolveRefresh(
                    refreshed: info,
                    lastAuthoritativeInfo: self.licenseInfo,
                    canUseFileFallback: self.agentInstaller.canUseStateFileFallback()
                ) {
                    self.loadLicenseFromFile()
                }
                self.agentResponding = info != nil
                self.isLoadingLicense = false
                self.updateStatusMessage()
            }
        }
    }

    // MARK: - Status Management

    func updateStatusMessage() {
        if let statusOverride = persistedStateAvailability.statusMessageOverride {
            statusMessage = statusOverride
            return
        }

        // Priority order for status:
        // 1. Agent not responding
        // 2. License issues
        // 3. Extension approval / restart notices
        // 4. Protection status, derived from the same ProtectionDisplayState
        //    that produces the headline

        if !agentResponding && agentInstalled {
            statusMessage = "Agent not responding"
            return
        }

        if let info = licenseInfo {
            if !info.isServiceAllowed {
                statusMessage = info.statusDescription
                return
            }
        }

        if let noticeStatus = extensionNotice.statusMessageOverride(
            isProtectionActive: protectionDisplayState.isProtectionActive,
            fallbackNeedsApproval: needsPermissionApproval
        ) {
            statusMessage = noticeStatus
            return
        }

        statusMessage = protectionDisplayState.statusPolicy.statusMessage
    }

    /// Refreshes resolver and provider state from the Agent's runtime snapshot.
    /// Never modifies isEnabled, which comes from persisted state only.
    ///
    /// Re-entrant invocations (called in parallel by persisted-state recovery,
    /// `Main.swift onAppear`, and SettingsView) would otherwise fire the whole
    /// chain, including `startResolver` and log lines, twice in a row. A check
    /// excludes others for as long as it runs, and its completion opens a short
    /// cooldown. A legitimate re-check a few seconds later still goes through.
    func checkServicesStatus() {
        guard !softwareUpdateSuspended else { return }
        UpdaterManager.shared.checkForUpdatesIfStale()
        guard persistedStateAvailability.allowsLifecycleActions else {
            requestPersistedStateRecoveryIfNeeded()
            updateStatusMessage()
            return
        }
        guard !isLoading,
            !isEnablingDNS,
            !isStoppingDNS,
            !isAutoStartingServices,
            serviceStatusCheckGate.shouldStart(
                isInFlight: isServiceStatusCheckInFlight,
                lastCompletedAt: serviceStatusCheckCompletedAt,
                now: ProcessInfo.processInfo.systemUptime
            )
        else { return }
        let lifecycleGeneration = dnsLifecycleGeneration
        resetRuntimeStateRefreshRetries()
        let wakeGeneration = serviceWakeupGate.advanceGeneration()
        serviceWakeGeneration = wakeGeneration
        isServiceStatusCheckInFlight = true

        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.isServiceStatusCheckInFlight = false
                self.serviceStatusCheckCompletedAt =
                    ProcessInfo.processInfo.systemUptime
            }
            await self.extensionManager.updateStatus()
            guard self.persistedStateAvailability.allowsLifecycleActions,
                self.isCurrentServiceStateRefresh(
                    capturedWakeGeneration: wakeGeneration,
                    capturedLifecycleGeneration: lifecycleGeneration
                )
            else { return }

            let runtimeResult = await XPCClient.shared.getRuntimeStateAsync()
            guard self.persistedStateAvailability.allowsLifecycleActions,
                !self.isLoading,
                self.isCurrentServiceStateRefresh(
                    capturedWakeGeneration: wakeGeneration,
                    capturedLifecycleGeneration: lifecycleGeneration
                )
            else { return }

            let running: Bool
            switch runtimeResult {
            case .success(let runtimeState):
                self.agentResponding = true
                self.scheduleRuntimeStateRefreshRetry(
                    for: runtimeState,
                    capturedWakeGeneration: wakeGeneration,
                    capturedLifecycleGeneration: lifecycleGeneration
                )
                guard !runtimeState.transitionInProgress else {
                    self.applyRuntimeStatePresentation(RuntimeStatePresentationPolicy.transitioning)
                    self.updateStatusMessage()
                    return
                }
                running = runtimeState.servicesRunning
                self.captivePortalDetected = runtimeState.captivePortalDetected
                self.applyRuntimeStatePresentation(
                    RuntimeStatePresentationPolicy.presentation(for: runtimeState)
                )
                self.extensionVersionStale =
                    ExtensionVersionStalePolicy(
                        runningVersion: runtimeState.proxyProviderVersion,
                        bundledVersion: self.extensionManager.bundledExtensionVersion,
                        proxyEnabled: self.extensionManager.proxyEnabled,
                        activationInProgress: self.extensionManager.isActivationInProgress
                    ).isStale
            case .failure(let error):
                self.agentResponding = false
                self.invalidateProviderStateAfterUnreadableRuntimeState()
                self.scheduleRuntimeStateRefreshRetry(
                    for: nil,
                    capturedWakeGeneration: wakeGeneration,
                    capturedLifecycleGeneration: lifecycleGeneration
                )
                self.logger.warning(
                    "Failed to check runtime state: \(error.localizedDescription, privacy: .public)"
                )
                self.updateStatusMessage()
                return
            }

            if running {
                guard self.isEnabled || self.isEnablingDNS else {
                    self.logger.warning("Resolver is running while DNS preference is disabled; stopping it")
                    self.stopResolverStartedWithoutEnabledPreference()
                    return
                }

                self.agentResponding = true
                self.servicesRunning = true
                self.updateStatusMessage()

                if !self.captivePortalDetected && !self.extensionManager.proxyEnabled {
                    Task { @MainActor in
                        guard self.persistedStateAvailability.allowsLifecycleActions,
                            !self.isStoppingDNS,
                            self.dnsLifecycleGeneration == lifecycleGeneration
                        else { return }
                        _ = await self.enableProxyAndContentFilter(for: lifecycleGeneration)
                        guard self.persistedStateAvailability.allowsLifecycleActions,
                            self.isCurrentDNSLifecycle(lifecycleGeneration)
                        else { return }
                        self.updateStatusMessage()
                    }
                } else if self.shouldEnableContentFilter {
                    self.enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                }

                self.loadLicenseInfo()
            } else {
                self.agentResponding = true
                self.servicesRunning = false
                self.updateStatusMessage()
                self.cancelPendingContentFilterEnable(clearNotice: false)
                Task { @MainActor in
                    guard self.persistedStateAvailability.allowsLifecycleActions,
                        self.dnsLifecycleGeneration == lifecycleGeneration
                    else { return }
                    await self.disableContentFilterIfNotNeeded()
                }

                let recoveryPolicy = ServiceRecoveryProxyPolicy(
                    isEnabled: self.isEnabled,
                    isUpdatingAgent: self.isUpdatingAgent,
                    isStoppingServices: self.isStoppingDNS,
                    dnsProxyEnabled: self.extensionManager.proxyEnabled,
                    persistedStateAvailability: self.persistedStateAvailability
                )

                // No immediate recovery will run, so disable the proxy and let DNS pass through.
                if recoveryPolicy.shouldDisableProxyBeforeAutoStart {
                    Task { @MainActor in
                        guard self.persistedStateAvailability.allowsLifecycleActions,
                            self.dnsLifecycleGeneration == lifecycleGeneration
                        else { return }
                        await self.disableDNSProxyAfterServiceStop()
                    }
                }

                if recoveryPolicy.shouldAttemptAutoStart && !self.isAutoStartingServices {
                    self.isAutoStartingServices = true
                    self.logger.info("Services not running but isEnabled=true, attempting to start...")
                    Task { @MainActor in
                        defer { self.isAutoStartingServices = false }
                        guard self.persistedStateAvailability.allowsLifecycleActions,
                            self.isCurrentDNSLifecycle(lifecycleGeneration)
                        else { return }

                        let success: Bool
                        switch await XPCClient.shared.startResolverAsync() {
                        case .success(let didStart):
                            success = didStart
                        case .failure(let error):
                            self.logger.error(
                                "Failed to auto-start services: \(error.localizedDescription, privacy: .public)"
                            )
                            success = false
                        }

                        guard self.persistedStateAvailability.allowsLifecycleActions,
                            self.isCurrentDNSLifecycle(lifecycleGeneration)
                        else {
                            if success {
                                await self.stopServicesAfterStaleStart(
                                    from: lifecycleGeneration,
                                    stopWhenPersistedStateUnavailable: true
                                )
                            }
                            return
                        }

                        if success {
                            self.logger.info("Services started successfully")
                            self.servicesRunning = true
                            self.agentResponding = true
                            if !self.extensionManager.proxyEnabled {
                                _ = await self.enableProxyAndContentFilter(for: lifecycleGeneration)
                                guard self.persistedStateAvailability.allowsLifecycleActions,
                                    self.isCurrentDNSLifecycle(lifecycleGeneration)
                                else {
                                    await self.stopServicesAfterStaleStart(
                                        from: lifecycleGeneration,
                                        stopWhenPersistedStateUnavailable: true
                                    )
                                    return
                                }
                                self.updateStatusMessage()
                            } else if self.shouldEnableContentFilter {
                                self.enableContentFilterInBackgroundIfNeeded(reason: "Block DoH & DoT")
                            }
                        } else {
                            self.logger.debug("Failed to auto-start services (license may be blocked)")
                            if recoveryPolicy.shouldDisableProxyAfterAutoStartFailure {
                                await self.disableDNSProxyAfterServiceStop()
                                self.updateStatusMessage()
                            }
                        }
                        self.updateStatusMessage()
                    }
                }

                self.loadLicenseInfo()
            }
        }
    }

    // MARK: - Cleanup / Uninstall

    /// Uninstall: removes what setup installed and macOS approved (LaunchAgent, Login Item,
    /// DNS Proxy and Content Filter configurations, system extensions) and the app's notifications.
    /// The notification and local network permissions stay, because no API revokes them.
    /// Returns the failure messages, empty when every step succeeded.
    func performFullCleanup() async -> [String] {
        guard !isStoppingDNS else {
            logger.warning("Full cleanup skipped because DNS teardown is already in progress")
            return ["DNS teardown is already in progress"]
        }

        var failures: [String] = []
        var rebootPending = false

        logger.info("Starting full cleanup...")
        servicesRemoved = true
        proxyControlBounceTask?.cancel()
        dnsLifecycleGeneration &+= 1
        runtimeDNSDesired = false
        isStoppingDNS = true
        resumeDNSAfterProxyApproval = false
        cancelPendingContentFilterEnable()
        defer { isStoppingDNS = false }
        // An install that finished after the uninstall would register the Agent again.
        _ = try? await runningAgentInstall?.value

        // 1. Remove the NEDNSProxyManager configuration first, before stopping
        // anything, so the configuration is never orphaned.
        do {
            try await removeDNSProxyConfiguration()
        } catch {
            logger.warning("Failed to remove DNS proxy config: \(error.localizedDescription, privacy: .public)")
            failures.append("Network configuration: \(error.localizedDescription)")
        }

        // 1b. Remove NEFilterManager configuration (Content Filter for DoH/DoT)
        do {
            try await FilterManager.shared.removeFilter()
        } catch {
            logger.warning("Failed to remove Content Filter config: \(error.localizedDescription, privacy: .public)")
            failures.append("Content Filter configuration: \(error.localizedDescription)")
        }

        // 2. Disable DNS Proxy (stops intercepting DNS immediately)
        // Note: This also disables Content Filter via ExtensionManager integration
        do {
            try await extensionManager.disableProxy()
            extensionActive = false
        } catch {
            logger.warning("Failed to disable proxy: \(error.localizedDescription, privacy: .public)")
            failures.append("DNS Proxy disable: \(error.localizedDescription)")
        }

        // 3. Stop the resolver with force=true (skips cache dump, fast shutdown)
        if agentInstalled {
            if case .failure(let error) = await XPCClient.shared.stopResolverAsync(force: true) {
                logger.warning("Cleanup resolver stop failed: \(error.localizedDescription, privacy: .public)")
            }
        }

        // 4. Unregister LaunchAgent (sends SIGTERM to agent)
        do {
            try await agentInstaller.uninstall()
            agentInstalled = false
            logger.info("Agent unregistered")
        } catch {
            if !CleanupOutcome.isExpectedAbsence(error) {
                failures.append("LaunchAgent: \(error.localizedDescription)")
            }
            logger.warning("LaunchAgent unregister failed: \(error.localizedDescription, privacy: .public)")
        }

        // 5. Reset XPC connection (agent is gone)
        XPCClient.shared.resetConnection()

        // 6. Remove Login Item (MacDNS.app)
        do {
            try await appLoginItem.unregister()
            logger.info("Login item removed")
        } catch {
            if !CleanupOutcome.isExpectedAbsence(error) {
                failures.append("Login item: \(error.localizedDescription)")
            }
            logger.debug("Login item removal: \(error.localizedDescription, privacy: .public)")
        }

        // 7. Deactivate System Extensions
        do {
            let result = try await deactivateSystemExtension(identifier: "app.macdns.dnsproxy")
            rebootPending = rebootPending || CleanupOutcome.needsReboot(result)
            logger.info("DNS Proxy deactivation result: \(result.rawValue, privacy: .public)")
        } catch {
            if !CleanupOutcome.isExpectedAbsence(error) {
                failures.append("DNS Proxy extension: \(error.localizedDescription)")
            }
            logger.debug("DNS Proxy extension deactivation: \(error.localizedDescription, privacy: .public)")
        }
        extensionManager.markSystemExtensionDeactivated()

        // 7b. Deactivate Content Filter System Extension
        do {
            let result = try await deactivateSystemExtension(identifier: "app.macdns.contentfilter")
            rebootPending = rebootPending || CleanupOutcome.needsReboot(result)
            logger.info("Content Filter deactivation result: \(result.rawValue, privacy: .public)")
        } catch {
            if !CleanupOutcome.isExpectedAbsence(error) {
                failures.append("Content Filter extension: \(error.localizedDescription)")
            }
            logger.debug("Content Filter extension deactivation: \(error.localizedDescription, privacy: .public)")
        }

        // 8. Remove the notifications MacDNS delivered or scheduled
        let notificationCenter = UNUserNotificationCenter.current()
        notificationCenter.removeAllPendingNotificationRequests()
        notificationCenter.removeAllDeliveredNotifications()

        isEnabled = false
        extensionActive = false
        invalidateProviderStateAfterUnreadableRuntimeState()
        cleanupRequiresRestart = rebootPending
        if rebootPending {
            statusMessage = "Restart your Mac to finish removing extensions"
        } else {
            statusMessage = failures.isEmpty ? "Cleanup complete" : "Some components could not be removed"
        }

        if !failures.isEmpty {
            let failureSummary = failures.joined(separator: ", ")
            let cleanupSummary = "Cleanup completed with \(failures.count) failure(s): \(failureSummary)"
            logger.warning("\(cleanupSummary, privacy: .public)")
        } else if rebootPending {
            logger.info("Cleanup requires a restart to finish extension removal")
        } else {
            logger.info("Cleanup completed successfully")
        }
        return failures
    }

    private func deactivateSystemExtension(identifier: String) async throws -> OSSystemExtensionRequest.Result {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<OSSystemExtensionRequest.Result, Error>) in
            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: identifier,
                queue: .main
            )

            let delegate = SystemExtensionDeactivationDelegate { result in
                switch result {
                case .success(let result):
                    continuation.resume(returning: result)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }

            // Keep delegate alive
            objc_setAssociatedObject(request, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)

            request.delegate = delegate
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func removeDNSProxyConfiguration() async throws {
        let proxyManager = NEDNSProxyManager.shared()

        try await proxyManager.loadFromPreferences()

        guard let proto = proxyManager.providerProtocol,
            proto.providerBundleIdentifier?.contains("macdns") == true
        else {
            logger.info("No MacDNS proxy config found to remove")
            return
        }

        if proxyManager.isEnabled {
            proxyManager.isEnabled = false
            do {
                try await proxyManager.saveToPreferences()
            } catch {
                logger.warning("Failed to disable DNS proxy: \(error.localizedDescription, privacy: .public)")
                // Continue with removal even if disable fails
            }
        }

        do {
            try await proxyManager.removeFromPreferences()
            logger.info("Removed DNS proxy config")
        } catch {
            logger.warning(
                "removeFromPreferences failed: \(error.localizedDescription, privacy: .public), forcing reset..."
            )
            proxyManager.providerProtocol = nil
            try await proxyManager.saveToPreferences()
            logger.info("Forced DNS proxy config reset (protocol = nil)")
        }
    }

}

// MARK: - System Extension Deactivation Delegate

class SystemExtensionDeactivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let completion: (Result<OSSystemExtensionRequest.Result, Error>) -> Void
    private var hasCompleted = false

    init(completion: @escaping (Result<OSSystemExtensionRequest.Result, Error>) -> Void) {
        self.completion = completion
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .cancel
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // For deactivation, this shouldn't happen, but handle it
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        guard !hasCompleted else { return }
        hasCompleted = true
        completion(.success(result))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard !hasCompleted else { return }
        hasCompleted = true
        completion(.failure(error))
    }
}
