// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Typed outcome of reading `license.json`.
///
/// A corrupt or unreadable file is never normalized into an empty state:
/// callers must latch fail-closed instead of treating it as a fresh install.
enum LicenseStateFileLoadResult {
    case missing
    case loaded(LicenseState)
    case invalid(String)
    case ioFailure(String)
}

enum LicenseFailClosedStateFileLoadResult {
    case missing
    case loaded(LicenseFailClosedState)
    case invalid(String)
    case ioFailure(String)
}

enum LicenseAdmissionJournalFileLoadResult {
    case missing
    case loaded(LicenseAdmissionJournalEntry)
    case invalid(String)
    case ioFailure(String)
}

/// Typed outcome of reading the trusted-time high-water mark.
///
/// "Never recorded" and "recorded but unreadable" are different facts. The
/// second is a tamper or I/O signal and must never degrade into the permissive
/// case where any wall clock is accepted. `lockFailure` means the read
/// transaction never opened, so nothing about the mark is known. The whole
/// license directory is then unusable and `load()` already latches fail-closed.
///
/// `missingWithPersistedLicense` separates a genuinely fresh installation from a
/// license that predates the sidecar or lost it. It carries the verified server
/// time that license already holds, so the mark can be rebuilt from it instead of
/// being lost. Both files are read inside the same exclusive lock, so the pair
/// cannot be observed mid-write.
enum LicenseTrustedTimeMarkLoadResult {
    case missing
    case missingWithPersistedLicense(lastValidatedAt: Date?)
    case loaded(LicenseTrustedTimeMark)
    case invalid(String)
    case ioFailure(String)
    case lockFailure(String)
}

struct LicenseAdmissionJournalEntry: Codable, Equatable, Sendable {
    let armedAt: Date
}

struct LicenseFailClosedState: Codable, Equatable, Sendable {
    let reason: LicenseFailClosedReason
    let engagedAt: Date?
}

/// Highest verified server time observed so far. Persisted so a wall-clock
/// rollback across boots is detectable.
struct LicenseTrustedTimeMark: Codable, Equatable, Sendable {
    let serverTime: Date
}

/// Reads and writes the persisted license state and its fail-closed sidecar.
///
/// Every file this store creates holds either the plaintext license key or a
/// durable admission decision, so all writes go through `writeAtomically`, which
/// creates both the temporary and the final file `0600` instead of inheriting the
/// launchd umask.
struct LicenseStateFileStore {
    let path: URL

    var failClosedPath: URL {
        path.appendingPathExtension("fail-closed")
    }

    var admissionJournalPath: URL {
        path.appendingPathExtension("admission-journal")
    }

    var trustedTimePath: URL {
        path.appendingPathExtension("trusted-time")
    }

    init(path: URL) {
        self.path = path
    }

    func load() -> LicenseStateFileLoadResult {
        do {
            return try StateFileLock.withExclusiveLock(stateFile: path) {
                switch loadData(at: path, label: "License path") {
                case .missing:
                    return .missing
                case .loaded(let data):
                    do {
                        return .loaded(
                            try JSONCoding.decoder.decode(
                                LicenseState.self,
                                from: data
                            )
                        )
                    } catch {
                        return .invalid(error.localizedDescription)
                    }
                case .ioFailure(let reason):
                    return .ioFailure(reason)
                }
            }
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }

    func save(_ state: LicenseState) -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                let data = try JSONCoding.encoder.encode(state)
                try writeAtomically(data, to: path)
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to save license state: \(error.localizedDescription)"
            )
            return false
        }
    }

    func loadAdmissionJournal() -> LicenseAdmissionJournalFileLoadResult {
        do {
            return try StateFileLock.withExclusiveLock(stateFile: path) {
                switch loadData(
                    at: admissionJournalPath,
                    label: "License admission journal path"
                ) {
                case .missing:
                    return .missing
                case .loaded(let data):
                    do {
                        return .loaded(
                            try JSONCoding.decoder.decode(
                                LicenseAdmissionJournalEntry.self,
                                from: data
                            )
                        )
                    } catch {
                        return .invalid(error.localizedDescription)
                    }
                case .ioFailure(let reason):
                    return .ioFailure(reason)
                }
            }
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }

    func saveAdmissionJournal(_ entry: LicenseAdmissionJournalEntry) -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                let data = try JSONCoding.encoder.encode(entry)
                try writeAtomically(data, to: admissionJournalPath)
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to save license admission journal: \(error.localizedDescription)"
            )
            return false
        }
    }

    func clearAdmissionJournal() -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                try removeFileIfPresent(
                    at: admissionJournalPath,
                    directoryError: "License admission journal path is a directory"
                )
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to clear license admission journal: \(error.localizedDescription)"
            )
            return false
        }
    }

    func loadFailClosedState() -> LicenseFailClosedStateFileLoadResult {
        do {
            return try StateFileLock.withExclusiveLock(stateFile: path) {
                switch loadData(
                    at: failClosedPath,
                    label: "License fail-closed path"
                ) {
                case .missing:
                    return .missing
                case .loaded(let data):
                    do {
                        return .loaded(
                            try JSONCoding.decoder.decode(
                                LicenseFailClosedState.self,
                                from: data
                            )
                        )
                    } catch {
                        return .invalid(error.localizedDescription)
                    }
                case .ioFailure(let reason):
                    return .ioFailure(reason)
                }
            }
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }

    func saveFailClosedState(_ state: LicenseFailClosedState) -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                let data = try JSONCoding.encoder.encode(state)
                try writeAtomically(data, to: failClosedPath)
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to save license fail-closed state: \(error.localizedDescription)"
            )
            return false
        }
    }

    func clearFailClosedState() -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                try removeFileIfPresent(
                    at: failClosedPath,
                    directoryError: "License fail-closed path is a directory"
                )
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to clear license fail-closed state: \(error.localizedDescription)"
            )
            return false
        }
    }

    func loadTrustedTimeMark() -> LicenseTrustedTimeMarkLoadResult {
        do {
            return try StateFileLock.withExclusiveLock(stateFile: path) {
                switch loadData(
                    at: trustedTimePath,
                    label: "License trusted time path"
                ) {
                case .missing:
                    guard
                        case .loaded(let data) = loadData(
                            at: path,
                            label: "License path"
                        )
                    else {
                        return .missing
                    }
                    let state = try? JSONCoding.decoder.decode(
                        LicenseState.self,
                        from: data
                    )
                    return .missingWithPersistedLicense(
                        lastValidatedAt: state?.lastValidatedAt
                    )
                case .loaded(let data):
                    do {
                        return .loaded(
                            try JSONCoding.decoder.decode(
                                LicenseTrustedTimeMark.self,
                                from: data
                            )
                        )
                    } catch {
                        return .invalid(error.localizedDescription)
                    }
                case .ioFailure(let reason):
                    return .ioFailure(reason)
                }
            }
        } catch {
            return .lockFailure(error.localizedDescription)
        }
    }

    func saveTrustedTimeMark(_ mark: LicenseTrustedTimeMark) -> Bool {
        do {
            try StateFileLock.withExclusiveLock(stateFile: path) {
                let data = try JSONCoding.encoder.encode(mark)
                try writeAtomically(data, to: trustedTimePath)
            }
            return true
        } catch {
            AgentLogger.shared.error(
                "Failed to save trusted license time: \(error.localizedDescription)"
            )
            return false
        }
    }

    private enum DataLoadResult {
        case missing
        case loaded(Data)
        case ioFailure(String)
    }

    /// Writes `data` so neither the temporary nor the final file is ever readable
    /// by another user, regardless of the launchd umask.
    private func writeAtomically(_ data: Data, to file: URL) throws {
        let permissions: [FileAttributeKey: Any] = [
            .posixPermissions: NSNumber(value: Int16(0o600))
        ]
        let temporary = file.deletingLastPathComponent()
            .appendingPathComponent(
                ".\(file.lastPathComponent).\(UUID().uuidString).tmp"
            )

        guard
            FileManager.default.createFile(
                atPath: temporary.path,
                contents: data,
                attributes: permissions
            )
        else {
            throw NSError(
                domain: "LicenseStateFileStore",
                code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Failed to create temporary license file at \(temporary.path)"
                ]
            )
        }

        guard rename(temporary.path, file.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(code),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Failed to replace \(file.lastPathComponent): \(String(cString: strerror(code)))"
                ]
            )
        }

        try FileManager.default.setAttributes(
            permissions,
            ofItemAtPath: file.path
        )
    }

    private func removeFileIfPresent(
        at file: URL,
        directoryError: String
    ) throws {
        var isDirectory: ObjCBool = false
        guard
            FileManager.default.fileExists(
                atPath: file.path,
                isDirectory: &isDirectory
            )
        else {
            return
        }
        guard !isDirectory.boolValue else {
            throw NSError(
                domain: "LicenseStateFileStore",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: directoryError]
            )
        }
        try FileManager.default.removeItem(at: file)
    }

    private func loadData(at file: URL, label: String) -> DataLoadResult {
        var isDirectory: ObjCBool = false
        guard
            FileManager.default.fileExists(
                atPath: file.path,
                isDirectory: &isDirectory
            )
        else {
            return .missing
        }
        guard !isDirectory.boolValue else {
            return .ioFailure("\(label) is a directory")
        }

        do {
            return .loaded(try Data(contentsOf: file))
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }
}
