// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Primary and backup download URLs for one blocklist file.
#[derive(Debug, Clone)]
pub struct BlocklistUrl {
    pub primary: String,
    pub backup: String,
}

impl BlocklistUrl {
    fn new(filename: &str) -> Self {
        // Mutable Hagezi refs are deliberate because users expect lists to stay
        // fresh hourly. Stronger supply-chain control belongs in a curated
        // mirror or manifest, not in pinning stale commits here.
        Self {
            primary: format!(
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/{}",
                filename
            ),
            backup: format!(
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/{}",
                filename
            ),
        }
    }
}

pub fn hagezi_urls(category: &str, level: &str) -> Vec<BlocklistUrl> {
    match (category, level) {
        ("ads_tracking", "light") => vec![BlocklistUrl::new("light.txt")],
        ("ads_tracking", "normal") => vec![BlocklistUrl::new("multi.txt")],
        ("ads_tracking", "pro") => vec![BlocklistUrl::new("pro.txt")],
        ("ads_tracking", "proplus") => vec![BlocklistUrl::new("pro.plus.txt")],
        ("ads_tracking", "ultimate") => vec![BlocklistUrl::new("ultimate.txt")],

        ("malware_security", "light") => vec![BlocklistUrl::new("fake.txt")],
        ("malware_security", "normal") => vec![
            BlocklistUrl::new("fake.txt"),
            BlocklistUrl::new("tif.mini.txt"),
        ],
        ("malware_security", "pro") => vec![
            BlocklistUrl::new("fake.txt"),
            BlocklistUrl::new("tif.medium.txt"),
        ],
        ("malware_security", "ultimate") => vec![
            BlocklistUrl::new("fake.txt"),
            BlocklistUrl::new("tif-1.txt"),
            BlocklistUrl::new("tif-2.txt"),
        ],

        // Single-level category: "light" means enabled.
        ("adult", "light") => vec![BlocklistUrl::new("nsfw.txt")],

        ("gambling", "light") => vec![BlocklistUrl::new("gambling.mini.txt")],
        ("gambling", "normal") => vec![BlocklistUrl::new("gambling.medium.txt")],
        ("gambling", "pro") => vec![BlocklistUrl::new("gambling.txt")],

        // Single-level category: "light" means enabled.
        ("social", "light") => vec![BlocklistUrl::new("social.txt")],

        ("misc", "light") => vec![BlocklistUrl::new("popupads.txt")],
        ("misc", "normal") => vec![
            BlocklistUrl::new("popupads.txt"),
            BlocklistUrl::new("urlshortener.txt"),
        ],
        ("misc", "pro") => vec![
            BlocklistUrl::new("popupads.txt"),
            BlocklistUrl::new("urlshortener.txt"),
            BlocklistUrl::new("doh.txt"),
        ],

        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ads_tracking_pro_returns_one_url() {
        let urls = hagezi_urls("ads_tracking", "pro");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].primary.contains("rpz/pro.txt"));
        assert!(urls[0].primary.contains("raw.githubusercontent.com"));
        assert!(urls[0].backup.contains("rpz/pro.txt"));
        assert!(urls[0].backup.contains("cdn.jsdelivr.net"));
    }

    #[test]
    fn malware_security_normal_returns_two_urls() {
        let urls = hagezi_urls("malware_security", "normal");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].primary.contains("rpz/fake.txt"));
        assert!(urls[1].primary.contains("rpz/tif.mini.txt"));
    }

    #[test]
    fn malware_security_ultimate_uses_split_tif_generation() {
        let urls = hagezi_urls("malware_security", "ultimate");
        let primary: Vec<_> = urls.iter().map(|url| url.primary.as_str()).collect();
        let backup: Vec<_> = urls.iter().map(|url| url.backup.as_str()).collect();

        assert_eq!(urls.len(), 3);
        assert_eq!(
            primary,
            vec![
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/fake.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-1.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-2.txt",
            ]
        );
        assert_eq!(
            backup,
            vec![
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/fake.txt",
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/tif-1.txt",
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/tif-2.txt",
            ]
        );
        assert!(urls.iter().all(|url| !url.primary.ends_with("/tif.txt")));
    }

    #[test]
    fn unknown_category_returns_empty() {
        let urls = hagezi_urls("nope", "none");
        assert!(urls.is_empty());
    }
}
