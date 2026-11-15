import Foundation

// The agent's config transaction. Every state-file write is serialized through
// the shared flock, so the agent and the App fallback cannot interleave.
struct ConfigStore {
    func save(_ config: FullConfig) throws {
        let encoded = try JSONEncoder().encode(config)
        try StateFileLock.withExclusiveLock {
            try encoded.write(to: PathResolver.stateFile)
        }
    }
}
