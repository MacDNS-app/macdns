// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! macdns path resolution. Mirrors Sources/Shared/PathResolver.swift.

fn home_env() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

fn macdns_base_path_with(home: &str) -> String {
    format!("{}/Library/Application Support/MacDNS", home)
}

fn blocklists_path_with(home: &str) -> String {
    format!("{}/blocklists", macdns_base_path_with(home))
}

fn allowlist_db_path_with(home: &str) -> String {
    format!("{}/allowlist.db", blocklists_path_with(home))
}

fn blocklist_settings_path_with(home: &str) -> String {
    format!("{}/blocklist_settings.json", macdns_base_path_with(home))
}

/// `~/Library/Application Support/MacDNS`
pub fn macdns_base_path() -> String {
    macdns_base_path_with(&home_env())
}

/// `~/Library/Application Support/MacDNS/blocklists`
pub fn blocklists_path() -> String {
    blocklists_path_with(&home_env())
}

/// `~/Library/Application Support/MacDNS/blocklists/allowlist.db`
pub fn allowlist_db_path() -> String {
    allowlist_db_path_with(&home_env())
}

/// `~/Library/Application Support/MacDNS/blocklist_settings.json`
pub fn blocklist_settings_path() -> String {
    blocklist_settings_path_with(&home_env())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nested_under_macdns_base() {
        let home = "/tmp/testhome";
        assert_eq!(
            macdns_base_path_with(home),
            "/tmp/testhome/Library/Application Support/MacDNS"
        );
        assert_eq!(
            blocklists_path_with(home),
            "/tmp/testhome/Library/Application Support/MacDNS/blocklists"
        );
        assert_eq!(
            allowlist_db_path_with(home),
            "/tmp/testhome/Library/Application Support/MacDNS/blocklists/allowlist.db"
        );
        assert_eq!(
            blocklist_settings_path_with(home),
            "/tmp/testhome/Library/Application Support/MacDNS/blocklist_settings.json"
        );
    }
}
