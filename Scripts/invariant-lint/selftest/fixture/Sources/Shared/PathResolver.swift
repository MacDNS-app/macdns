import Foundation

// The only place that names a config file or the support directory.
enum PathResolver {
    static var supportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MacDNS")
    }

    static var stateFile: URL {
        supportDirectory.appendingPathComponent("state.json")
    }

    static var blocklistSettingsFile: URL {
        supportDirectory.appendingPathComponent("blocklist_settings.json")
    }
}
