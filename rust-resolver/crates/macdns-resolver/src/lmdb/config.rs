// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockAction {
    #[default]
    Null,
    Nxdomain,
    Localhost,
    CustomIp(IpAddr),
}

impl Serialize for BlockAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            BlockAction::Null => serializer.serialize_str("null"),
            BlockAction::Nxdomain => serializer.serialize_str("nxdomain"),
            BlockAction::Localhost => serializer.serialize_str("localhost"),
            BlockAction::CustomIp(ip) => serializer.serialize_str(&ip.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for BlockAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "null" => Ok(BlockAction::Null),
            "nxdomain" => Ok(BlockAction::Nxdomain),
            "localhost" => Ok(BlockAction::Localhost),
            ip => {
                let addr: IpAddr = ip.parse().map_err(serde::de::Error::custom)?;
                Ok(BlockAction::CustomIp(addr))
            }
        }
    }
}

/// Result of a domain block check. `tag` comes from the matching
/// `BlocklistEntry`.
#[derive(Debug, Clone)]
pub struct BlockMatch {
    pub action: BlockAction,
    /// Opaque tag, logged as `category=<tag>`. Never interpreted by the core.
    pub tag: String,
    pub matched_rule: String,
}

/// One blocklist entry in the generic runtime config. `tag` is an opaque
/// string emitted in the BLOCKED log. Downstream consumers may expect a known
/// identifier, but the core never interprets it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    pub name: String,
    pub tag: String,
    pub db_path: PathBuf,
    pub action: BlockAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub blocklists: Vec<BlocklistEntry>,
}

#[cfg(test)]
mod new_schema_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_generic_runtime_config_json() {
        let json = r#"{
            "enabled": true,
            "blocklists": [
                {
                    "name": "Ads & Tracking Normal",
                    "tag": "ads_tracking",
                    "db_path": "/abs/blocklists/ads_tracking_multi.db",
                    "action": "nxdomain"
                },
                {
                    "name": "Malware & Security Pro",
                    "tag": "malware_security",
                    "db_path": "/abs/blocklists/malware_security_tif.medium.db",
                    "action": "192.168.1.1"
                }
            ]
        }"#;
        let cfg: BlocklistConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.blocklists.len(), 2);
        assert_eq!(cfg.blocklists[0].name, "Ads & Tracking Normal");
        assert_eq!(cfg.blocklists[0].tag, "ads_tracking");
        assert_eq!(
            cfg.blocklists[0].db_path,
            PathBuf::from("/abs/blocklists/ads_tracking_multi.db")
        );
        assert_eq!(cfg.blocklists[0].action, BlockAction::Nxdomain);
        assert_eq!(cfg.blocklists[1].tag, "malware_security");
        assert_eq!(
            cfg.blocklists[1].db_path,
            PathBuf::from("/abs/blocklists/malware_security_tif.medium.db")
        );
        match cfg.blocklists[1].action {
            BlockAction::CustomIp(ip) => assert_eq!(ip.to_string(), "192.168.1.1"),
            other => panic!("expected CustomIp, got {:?}", other),
        }
    }

    #[test]
    fn action_string_deserialization() {
        let nx: BlockAction = serde_json::from_str("\"nxdomain\"").unwrap();
        assert_eq!(nx, BlockAction::Nxdomain);
        let lh: BlockAction = serde_json::from_str("\"localhost\"").unwrap();
        assert_eq!(lh, BlockAction::Localhost);
        let ip: BlockAction = serde_json::from_str("\"192.168.1.1\"").unwrap();
        match ip {
            BlockAction::CustomIp(addr) => assert_eq!(addr.to_string(), "192.168.1.1"),
            other => panic!("expected CustomIp, got {:?}", other),
        }
    }

    #[test]
    fn null_action_round_trips_as_a_string() {
        let action: BlockAction = serde_json::from_str("\"null\"").unwrap();
        assert_eq!(serde_json::to_string(&action).unwrap(), "\"null\"");
        assert_eq!(BlockAction::default(), action);
    }
}

#[cfg(test)]
mod block_match_log_format {
    use super::*;

    #[test]
    fn block_match_exposes_tag_for_logging() {
        let m = BlockMatch {
            action: BlockAction::Nxdomain,
            tag: "ads_tracking".to_string(),
            matched_rule: "example.com".to_string(),
        };
        let log_line = format!(
            "BLOCKED: domain={} rule={} category={}",
            "foo.example.com", m.matched_rule, m.tag
        );
        assert_eq!(
            log_line,
            "BLOCKED: domain=foo.example.com rule=example.com category=ads_tracking"
        );
    }
}
