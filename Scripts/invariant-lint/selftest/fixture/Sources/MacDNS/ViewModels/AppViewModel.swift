import Foundation

@MainActor
final class AppViewModel: ObservableObject {
    @Published var statusMessage = ""
    var protectionDisplayState = ProtectionDisplayState(providerState: .unknown)
    private let healthQueue = DispatchQueue(label: "app.macdns.app.health")

    // A Darwin notification is an unauthenticated hint: the callback may only
    // hand work off, never change displayed state.
    func observeBypassHints() {
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let model = Unmanaged<AppViewModel>.fromOpaque(observer).takeUnretainedValue()
                model.enqueueHealthEvaluation()
            },
            "app.macdns.bypass-disable" as CFString,
            nil,
            .deliverImmediately)
    }

    func enqueueHealthEvaluation() {
        healthQueue.async { [weak self] in
            self?.refreshRuntimeState()
        }
    }

    func refreshRuntimeState() {
        updateStatusMessage()
    }

    func updateStatusMessage() {
        statusMessage = protectionDisplayState.statusPolicy.statusMessage
    }

    // ALLOWLIST SUBJECT for J07: a 24h notification cooldown timestamp. It is a
    // presentation timestamp, never read back as configuration.
    func sendNotificationOnce(_ key: String) {
        let last = UserDefaults.standard.double(forKey: key)
        guard Date().timeIntervalSince1970 - last > 86_400 else { return }
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: key)
    }
}
