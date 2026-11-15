import Foundation

// Wire shape of the bootstrap the provider hands the agent. The raw key travels
// as `Data` here because this is a serialized payload, not the live key — which
// is why J13's "unwipeable Data" check is scoped to the session type.
struct ProxyControlBootstrap: Codable {
    let version: UInt16
    let sessionID: Data
    var hmacKey: Data
}

@objc protocol ProxyControlProtocol {
    func beginControlSession(withReply reply: @escaping (Data?) -> Void)
}
