// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

struct LicenseInfoFileFallbackOutcome {
    let info: LicenseInfo?
    let failureDescription: String?
}

enum LicenseInfoLoadFailurePolicy {
    static func resolve(
        lastAuthoritativeInfo: LicenseInfo?,
        canUseFileFallback: Bool,
        loadFileFallback: () -> LicenseInfo?
    ) -> LicenseInfo? {
        guard canUseFileFallback else {
            return lastAuthoritativeInfo ?? failClosedInfo()
        }
        return loadFileFallback()
    }

    /// A refresh that returns no info is a failure, never permission: the UI
    /// must not fall back to "service allowed" because it could not read
    /// authoritative license state.
    static func resolveRefresh(
        refreshed: LicenseInfo?,
        lastAuthoritativeInfo: LicenseInfo?,
        canUseFileFallback: Bool,
        loadFileFallback: () -> LicenseInfo?
    ) -> LicenseInfo? {
        guard let refreshed else {
            return resolve(
                lastAuthoritativeInfo: lastAuthoritativeInfo,
                canUseFileFallback: canUseFileFallback,
                loadFileFallback: loadFileFallback
            )
        }
        return refreshed
    }

    static func failClosedInfo() -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(status: .unknown),
            isServiceAllowed: false
        )
    }
}

struct LicenseInfoFileFallback {
    let path: URL

    private var failClosedPath: URL {
        path.appendingPathExtension("fail-closed")
    }

    private var admissionJournalPath: URL {
        path.appendingPathExtension("admission-journal")
    }

    func load() -> LicenseInfoFileFallbackOutcome {
        // Before the Agent first runs the support directory does not exist and
        // the lock file cannot be created. That is a fresh install, not an
        // unreadable license.
        guard
            FileManager.default.fileExists(
                atPath: path.deletingLastPathComponent().path
            )
        else {
            return LicenseInfoFileFallbackOutcome(info: nil, failureDescription: nil)
        }
        do {
            return try StateFileLock.withExclusiveLock(stateFile: path) {
                resolve(
                    license: loadLicenseState(),
                    failClosed: loadSidecar(
                        at: failClosedPath,
                        as: FailClosedSidecar.self,
                        label: "License fail-closed path"
                    ),
                    admissionJournal: loadSidecar(
                        at: admissionJournalPath,
                        as: AdmissionJournalSidecar.self,
                        label: "License admission journal path"
                    )
                )
            }
        } catch {
            return blockedOutcome(reason: error.localizedDescription)
        }
    }

    private func resolve(
        license: LicenseLoadResult,
        failClosed: SidecarLoadResult,
        admissionJournal: SidecarLoadResult
    ) -> LicenseInfoFileFallbackOutcome {
        let sidecarBlockReason =
            failClosed.blockReason(label: "License fail-closed marker")
            ?? admissionJournal.blockReason(label: "License admission journal")

        switch license {
        case .missing:
            guard let sidecarBlockReason else {
                return LicenseInfoFileFallbackOutcome(
                    info: nil,
                    failureDescription: nil
                )
            }
            return blockedOutcome(reason: sidecarBlockReason)

        case .loaded(let state):
            return LicenseInfoFileFallbackOutcome(
                info: LicenseInfo(
                    from: state,
                    isServiceAllowed: sidecarBlockReason == nil && state.isActive
                ),
                failureDescription: sidecarBlockReason
            )

        case .invalid(let reason), .ioFailure(let reason):
            return blockedOutcome(reason: reason)
        }
    }

    private func blockedOutcome(reason: String) -> LicenseInfoFileFallbackOutcome {
        LicenseInfoFileFallbackOutcome(
            info: LicenseInfoLoadFailurePolicy.failClosedInfo(),
            failureDescription: reason
        )
    }

    private func loadLicenseState() -> LicenseLoadResult {
        switch loadData(at: path, label: "License path") {
        case .missing:
            return .missing
        case .loaded(let data):
            do {
                return .loaded(
                    try JSONCoding.decoder.decode(LicenseState.self, from: data)
                )
            } catch {
                return .invalid(error.localizedDescription)
            }
        case .ioFailure(let reason):
            return .ioFailure(reason)
        }
    }

    private func loadSidecar<T: Decodable>(
        at path: URL,
        as type: T.Type,
        label: String
    ) -> SidecarLoadResult {
        switch loadData(at: path, label: label) {
        case .missing:
            return .missing
        case .loaded(let data):
            do {
                _ = try JSONCoding.decoder.decode(type, from: data)
                return .present
            } catch {
                return .invalid(error.localizedDescription)
            }
        case .ioFailure(let reason):
            return .ioFailure(reason)
        }
    }

    private func loadData(at path: URL, label: String) -> DataLoadResult {
        var isDirectory: ObjCBool = false
        guard
            FileManager.default.fileExists(
                atPath: path.path,
                isDirectory: &isDirectory
            )
        else {
            return .missing
        }
        guard !isDirectory.boolValue else {
            return .ioFailure("\(label) is a directory")
        }

        do {
            return .loaded(try Data(contentsOf: path))
        } catch {
            return .ioFailure(error.localizedDescription)
        }
    }

    private enum LicenseLoadResult {
        case missing
        case loaded(LicenseState)
        case invalid(String)
        case ioFailure(String)
    }

    private enum SidecarLoadResult {
        case missing
        case present
        case invalid(String)
        case ioFailure(String)

        func blockReason(label: String) -> String? {
            switch self {
            case .missing:
                return nil
            case .present:
                return "\(label) is present"
            case .invalid(let reason):
                return "\(label) is invalid: \(reason)"
            case .ioFailure(let reason):
                return "\(label) could not be read: \(reason)"
            }
        }
    }

    private enum DataLoadResult {
        case missing
        case loaded(Data)
        case ioFailure(String)
    }

    private struct FailClosedSidecar: Decodable {
        let reason: Reason
        let engagedAt: Date?

        enum Reason: String, Decodable {
            case stateLoadFailed
            case statePersistenceFailed
            case networkGraceExpired
        }
    }

    private struct AdmissionJournalSidecar: Decodable {
        let armedAt: Date
    }
}
