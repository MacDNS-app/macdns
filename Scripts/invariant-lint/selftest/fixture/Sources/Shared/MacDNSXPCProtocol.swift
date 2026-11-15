import Foundation

let macdnsAgentMachService = "app.macdns.agent"

@objc protocol MacDNSXPCProtocol {
    func getRuntimeState(withReply reply: @escaping (Data?) -> Void)
    func saveFullConfig(_ payload: Data, withReply reply: @escaping (Int) -> Void)
}
