import Foundation

// The agent's Mach service listener. Every peer is validated by audit token
// before the connection is resumed.
final class AgentListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        guard CodeSignValidator.shared.validate(connection: newConnection) else { return false }
        newConnection.exportedInterface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        newConnection.exportedObject = AgentService()
        newConnection.resume()
        return true
    }
}

enum AgentMain {
    static func main() {
        let listener = NSXPCListener(machServiceName: macdnsAgentMachService)
        listener.delegate = AgentListenerDelegate()
        listener.resume()
        RunLoop.main.run()
    }
}
