// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import os.log

public enum PathResolver {
    // MARK: - User Directories

    /// ~/Library/Application Support/MacDNS/
    public static var applicationSupportDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MacDNS")
    }

    /// ~/Library/Logs/MacDNS/
    public static var logDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/MacDNS")
    }

    // MARK: - Configuration Files

    /// ~/Library/Application Support/MacDNS/state.json
    public static var stateFile: URL {
        applicationSupportDir.appendingPathComponent("state.json")
    }

    /// ~/Library/Application Support/MacDNS/dns-proxy.dump
    ///
    /// Gzipped postcard dump of the in-process Rust resolver cache. Keeps the
    /// legacy `dns-proxy.dump` name so existing installs restore a warm cache
    /// instead of cold-starting.
    public static var resolverCacheFile: URL {
        applicationSupportDir.appendingPathComponent("dns-proxy.dump")
    }

    /// ~/Library/Application Support/MacDNS/query-history.sqlite
    ///
    /// Lookup history owned by the Rust resolver (SQLite, with `-wal`/`-shm`
    /// sidecars). The App never opens it. It reads history through the agent.
    public static var queryHistoryDB: URL {
        applicationSupportDir.appendingPathComponent("query-history.sqlite")
    }

    /// ~/Library/Application Support/MacDNS/blocklist_settings.json
    public static var blocklistSettings: URL {
        applicationSupportDir.appendingPathComponent("blocklist_settings.json")
    }

    /// ~/Library/Application Support/MacDNS/blocklists/
    public static var blocklistsDir: URL {
        applicationSupportDir.appendingPathComponent("blocklists")
    }

    /// ~/Library/Application Support/MacDNS/blocklists/allowlist.db
    public static var allowlistDB: URL {
        applicationSupportDir
            .appendingPathComponent("blocklists")
            .appendingPathComponent("allowlist.db")
    }

    /// ~/Library/Application Support/MacDNS/license.json
    public static var licenseFile: URL {
        applicationSupportDir.appendingPathComponent("license.json")
    }

    // MARK: - Bundled Resources (in MacDNS.app/Contents/Resources/)

    public enum PathError: LocalizedError {
        case resourcesNotFound(searchedPaths: [String])

        public var errorDescription: String? {
            switch self {
            case .resourcesNotFound(let paths):
                return "Could not locate app bundle resources. Searched: \(paths.joined(separator: ", "))"
            }
        }
    }

    private static var _resourcesDir: String?
    private static var _resourcesDirError: PathError?

    /// Resolves the app bundle's Resources directory.
    /// Works for both the main app and the agent executable. The resolver
    /// dylib (`libmacdns_resolver.dylib`) is the anchor file: it is always
    /// present in a correctly built bundle, so locating it proves we found
    /// the real Resources directory rather than a neighboring folder.
    private static var resourcesDir: String {
        if let cached = _resourcesDir {
            return cached
        }

        // A failed lookup is not retried. The placeholder makes later binary
        // access fail cleanly.
        if _resourcesDirError != nil {
            return "/nonexistent/resources"
        }

        var searchedPaths: [String] = []

        // Main app.
        if let resourcePath = Bundle.main.resourcePath {
            searchedPaths.append(resourcePath)
            if FileManager.default.fileExists(atPath: resourcePath + "/libmacdns_resolver.dylib") {
                _resourcesDir = resourcePath
                return resourcePath
            }
        }

        // For agent executable: MacDNS.app/Contents/MacOS/MacDNSAgent
        // Resources are at: MacDNS.app/Contents/Resources/
        let executablePath = Bundle.main.executablePath ?? ""
        let macOSDir = (executablePath as NSString).deletingLastPathComponent
        let contentsDir = (macOSDir as NSString).deletingLastPathComponent
        let resourcePath = contentsDir + "/Resources"
        searchedPaths.append(resourcePath)

        if FileManager.default.fileExists(atPath: resourcePath + "/libmacdns_resolver.dylib") {
            _resourcesDir = resourcePath
            return resourcePath
        }

        _resourcesDirError = .resourcesNotFound(searchedPaths: searchedPaths)
        if let errorDescription = _resourcesDirError?.errorDescription {
            let logger = Logger(subsystem: "app.macdns", category: "PathResolver")
            logger.error("Failed to locate resources: \(errorDescription, privacy: .public)")
        }
        return "/nonexistent/resources"
    }

    public static var resourcesAvailable: Bool {
        _ = resourcesDir  // Trigger resolution
        return _resourcesDirError == nil
    }

    public static var resourcesError: PathError? {
        _ = resourcesDir  // Trigger resolution
        return _resourcesDirError
    }

    public static var resolverDylib: String {
        resourcesDir + "/libmacdns_resolver.dylib"
    }

    // MARK: - Helper Methods

    public static func ensureDirectoriesExist() throws {
        let fm = FileManager.default

        if !fm.fileExists(atPath: applicationSupportDir.path) {
            try fm.createDirectory(
                at: applicationSupportDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        }

        if !fm.fileExists(atPath: logDir.path) {
            try fm.createDirectory(
                at: logDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        }

        if !fm.fileExists(atPath: blocklistsDir.path) {
            try fm.createDirectory(
                at: blocklistsDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        }
    }
}
