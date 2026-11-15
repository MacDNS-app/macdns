import Foundation
import ServiceManagement

// A user LaunchAgent, registered through SMAppService.agent.
enum AgentInstaller {
    static func register() throws {
        try SMAppService.agent(plistName: "app.macdns.agent.plist").register()
    }
}
