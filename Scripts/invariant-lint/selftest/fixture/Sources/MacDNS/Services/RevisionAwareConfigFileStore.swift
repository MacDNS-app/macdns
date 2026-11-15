import Foundation

// The App fallback's only writer of the state file, and only under the lock.
struct RevisionAwareConfigFileStore {
    func save(_ data: Data, revision: Int) throws {
        try StateFileLock.withExclusiveLock {
            try data.write(to: PathResolver.stateFile)
        }
    }
}
