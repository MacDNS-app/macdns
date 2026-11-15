// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

public enum StateFileLoadResult {
    case missing
    case valid([String: Any])
    case invalid(String)
    case ioFailure(String)
}

public enum StateFileLock {
    private static let registryLock = NSLock()
    private static var processLocks: [String: NSRecursiveLock] = [:]
    private static let recursionDepthKeyPrefix = "app.macdns.state-file-lock-depth."

    /// Recursive in-process lock for one canonical lock-file path. Unrelated
    /// files get unrelated locks, so a full-config transaction cannot delay
    /// license I/O. Nesting different files on one thread is allowed but must
    /// always use the same order, otherwise two threads can deadlock.
    private static func processLock(forKey key: String) -> NSRecursiveLock {
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = processLocks[key] { return existing }
        let created = NSRecursiveLock()
        processLocks[key] = created
        return created
    }

    public static func withExclusiveLock<T>(
        stateFile: URL,
        _ operation: () throws -> T
    ) throws -> T {
        let lockFile = stateFile.appendingPathExtension("lock")
        let key = lockFile.resolvingSymlinksInPath().standardizedFileURL.path
        let lock = processLock(forKey: key)
        lock.lock()
        defer { lock.unlock() }

        let threadDictionary = Thread.current.threadDictionary
        let recursionDepthKey = recursionDepthKeyPrefix + key
        let recursionDepth = threadDictionary[recursionDepthKey] as? Int ?? 0
        if recursionDepth > 0 {
            threadDictionary[recursionDepthKey] = recursionDepth + 1
            defer { threadDictionary[recursionDepthKey] = recursionDepth }
            return try operation()
        }

        let descriptor = lockFile.path.withCString {
            Darwin.open($0, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        }
        guard descriptor >= 0 else {
            throw posixError(operation: "open", path: lockFile.path)
        }
        defer { Darwin.close(descriptor) }

        guard flock(descriptor, LOCK_EX) == 0 else {
            throw posixError(operation: "flock", path: lockFile.path)
        }
        threadDictionary[recursionDepthKey] = 1
        defer {
            threadDictionary.removeObject(forKey: recursionDepthKey)
            flock(descriptor, LOCK_UN)
        }
        return try operation()
    }

    public static func load(stateFile: URL) -> StateFileLoadResult {
        do {
            return try withExclusiveLock(stateFile: stateFile) {
                loadUnlocked(stateFile: stateFile)
            }
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }

    public static func loadUnlocked(stateFile: URL) -> StateFileLoadResult {
        var isDirectory: ObjCBool = false
        guard
            FileManager.default.fileExists(
                atPath: stateFile.path,
                isDirectory: &isDirectory
            )
        else {
            return .missing
        }
        guard !isDirectory.boolValue else {
            return .ioFailure("State file path is a directory")
        }

        let data: Data
        do {
            data = try Data(contentsOf: stateFile)
        } catch {
            return .ioFailure(error.localizedDescription)
        }

        do {
            let object = try JSONSerialization.jsonObject(with: data)
            guard let config = object as? [String: Any] else {
                return .invalid("State file root is not a JSON object")
            }
            return .valid(config)
        } catch {
            return .invalid(error.localizedDescription)
        }
    }

    private static func posixError(
        operation: String,
        path: String
    ) -> NSError {
        let code = errno
        return NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(code),
            userInfo: [
                NSLocalizedDescriptionKey:
                    "\(operation) failed for \(path): \(String(cString: strerror(code)))"
            ]
        )
    }
}
