// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

@main
class AgentMain: NSObject, NSXPCListenerDelegate {
    // Held statically so the sources are never deallocated.
    private static var sigTermSource: DispatchSourceSignal?
    private static var sigIntSource: DispatchSourceSignal?

    /// Unlike signal() handlers, DispatchSource handlers can call async code,
    /// take locks and allocate without risking deadlock.
    private static func setupSignalHandlers() {
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)

        // launchd sends SIGTERM on unregister.
        sigTermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigTermSource?.setEventHandler {
            AgentLogger.shared.info("Received SIGTERM, shutting down...")
            MacDNSAgent.shared.shutdownServices()
            exit(0)
        }
        sigTermSource?.resume()

        sigIntSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigIntSource?.setEventHandler {
            AgentLogger.shared.info("Received SIGINT, shutting down...")
            MacDNSAgent.shared.shutdownServices()
            exit(0)
        }
        sigIntSource?.resume()
    }

    static func main() {
        // Seed RUST_BACKTRACE before the resolver dylib loads so the Rust
        // panic hook's Backtrace::force_capture() yields a populated frame
        // list. overwrite=0 preserves an operator-provided value.
        setenv("RUST_BACKTRACE", "full", 0)

        let delegate = AgentMain()

        setupSignalHandlers()

        let descriptorLimit = AgentFileDescriptorLimit.raise()
        if descriptorLimit < AgentFileDescriptorLimit.target {
            AgentLogger.shared.warning(
                "File descriptor limit is \(descriptorLimit), below the \(AgentFileDescriptorLimit.target) the resolver is sized for"
            )
        }

        // Register the XPC listener before any long-running work so launchd
        // does not treat the agent as unresponsive.
        let listener = NSXPCListener(machServiceName: "app.macdns.agent")
        listener.delegate = delegate
        listener.resume()
        AgentLogger.shared.info("MacDNSAgent XPC listener registered")

        // The resolver builds its configuration from state.json at start().
        // Only the allowlist, which lives in LMDB, is synced here.
        let allowlistSyncStartedAt = ProcessInfo.processInfo.systemUptime
        MacDNSAgent.shared.syncAllowlistToLMDB()
        let allowlistSyncElapsed =
            ProcessInfo.processInfo.systemUptime - allowlistSyncStartedAt
        AgentLogger.shared.info(
            String(
                format: "Allowlist startup sync completed in %.1fs",
                allowlistSyncElapsed
            )
        )

        // initialize() loads license state from disk and must finish before
        // restoreServicesIfEnabled() reads it.
        Task {
            await LicenseManager.shared.initialize()

            await MacDNSAgent.shared.restoreServicesIfEnabled()
            AgentLogger.shared.info("MacDNSAgent fully initialized")
        }

        RunLoop.main.run()
    }

    func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        guard CodeSignValidator.validateConnection(newConnection) else {
            AgentLogger.shared.error("Rejecting XPC connection from unauthorized process")
            let info = CodeSignValidator.getCodeSigningInfo(newConnection)
            AgentLogger.shared.error("Code signing info: \(info)")
            return false
        }

        let exportedInterface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        FullConfigPayloadPolicy.restrictPayloadClasses(on: exportedInterface)
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = MacDNSAgent.shared
        newConnection.resume()

        AgentLogger.shared.debug("Accepted XPC connection from authorized MacDNS.app")
        return true
    }
}
