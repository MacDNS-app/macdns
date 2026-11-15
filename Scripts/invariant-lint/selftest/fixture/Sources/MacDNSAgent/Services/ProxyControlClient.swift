import Foundation

// Installs the provider's session material into the resolver and keeps no copy.
final class ProxyControlClient {
    func installSession(_ data: Data?) {
        guard let data,
            var boot = try? JSONDecoder().decode(ProxyControlBootstrap.self, from: data),
            boot.sessionID.count == 16, boot.hmacKey.count == 32
        else {
            AgentLogger.shared.warning("Invalid control bootstrap; retrying")
            return
        }
        let installed = ResolverModule.shared.configureProxyControl(
            sessionID: boot.sessionID, key: boot.hmacKey)
        // The resolver owns the key from here on; the agent keeps no copy.
        boot.hmacKey.resetBytes(in: 0..<boot.hmacKey.count)
        if !installed {
            AgentLogger.shared.error("Failed to install the control session")
        }
    }
}
