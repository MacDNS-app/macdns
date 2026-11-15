import Foundation

// App-side XPC client. In scope for J12: no PID-based identity anywhere here.
final class XPCClient {
    private var connection: NSXPCConnection?

    func connect() {
        let link = NSXPCConnection(machServiceName: macdnsAgentMachService)
        link.remoteObjectInterface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        link.resume()
        connection = link
    }
}
