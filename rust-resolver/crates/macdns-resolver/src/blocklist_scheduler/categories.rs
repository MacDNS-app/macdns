// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! MacDNS category vocabulary. The identifiers and levels match the ones the
//! UI shows and `blocklist_settings.json` stores.
//!
//! The core LMDB layer (`crate::lmdb`) knows none of this.

use serde::{Deserialize, Serialize};

/// One row of the macdns blocklist_settings.json `categories` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacdnsCategoryConfig {
    pub name: String,
    pub identifier: String,
    pub level: String,
    #[serde(default = "default_action")]
    pub action: String,
    pub enabled: bool,
}

fn default_action() -> String {
    "null".to_string()
}

/// Schema version of `blocklist_settings.json` this resolver understands.
/// Bump it only when the on-disk shape changes in a way that needs a
/// migration in code. Swift writers set `version` to the schema they emit. A
/// higher version still loads but logs a warning, so a file from a newer
/// writer does not misparse silently.
pub const SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Root of blocklist_settings.json (the macdns on-disk format).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MacdnsBlocklistSettings {
    /// Schema version. `#[serde(default)]` keeps backward compatibility
    /// with files written before the field existed (treated as v1).
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub categories: Vec<MacdnsCategoryConfig>,
    #[serde(default)]
    pub db_base_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example_settings_json() {
        let json = r#"{
            "enabled": true,
            "db_base_path": "/abs/blocklists",
            "categories": [
                {
                    "name": "Ads & Tracking",
                    "identifier": "ads_tracking",
                    "level": "pro",
                    "action": "nxdomain",
                    "enabled": true
                },
                {
                    "name": "Adult",
                    "identifier": "adult",
                    "level": "light",
                    "enabled": false
                }
            ]
        }"#;
        let s: MacdnsBlocklistSettings = serde_json::from_str(json).unwrap();
        assert!(s.enabled);
        assert_eq!(s.categories.len(), 2);
        assert_eq!(s.categories[0].identifier, "ads_tracking");
        assert_eq!(s.categories[0].action, "nxdomain");
        assert_eq!(s.categories[1].action, "null");
        assert!(!s.categories[1].enabled);
    }
}
