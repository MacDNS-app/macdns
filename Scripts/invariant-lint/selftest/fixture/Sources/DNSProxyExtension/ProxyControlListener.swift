import Foundation
import os

// The proxy-control XPC listener. It runs inside the NE sandbox, where the
// Security framework's process lookup is denied, so the peer is validated with
// the connection's code-signing requirement rather than CodeSignValidator.
final class ProxyControlListener: NSObject, NSXPCListenerDelegate {
    private let logger = Logger(subsystem: "app.macdns.dnsproxy", category: "control")
    private var session: ProxyControlSession?

    func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        newConnection.setCodeSigningRequirement(agentRequirement)
        newConnection.exportedInterface = NSXPCInterface(with: ProxyControlProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    func beginControlSession(withReply reply: @escaping (Data?) -> Void) {
        guard let newSession = ProxyControlSession.generate() else {
            reply(nil)
            return
        }
        session = newSession
        // The staged copy of the raw key is wiped as soon as it is encoded.
        let encoded = newSession.hmacKey.withUnsafeBytes { raw -> String in
            var staged = Data(raw)
            defer { staged.resetBytes(in: 0..<staged.count) }
            return staged.base64EncodedString()
        }
        logger.info("Issued a control session")
        reply(bootstrapPayload(encoded))
    }
}
