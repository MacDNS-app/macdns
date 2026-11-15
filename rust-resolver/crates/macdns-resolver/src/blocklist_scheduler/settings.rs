// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Translation from blocklist_settings.json (macdns format) into the
//! in-memory `BlocklistConfig` consumed by the scheduler.

use super::categories::MacdnsBlocklistSettings;
use crate::lmdb::paths::{resolve_current_db_path, resolve_existing_current_db_path};
use crate::lmdb::{BlockAction, BlocklistConfig, BlocklistEntry, BlocklistError, Result};
use std::path::{Component, Path, PathBuf};

const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_CATEGORIES: usize = 128;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum FullTifGeneration {
    NotSelected,
    FakeOnly,
    Legacy,
    Split { retired_stable_present: bool },
}

impl FullTifGeneration {
    pub(super) fn migration_pending(self) -> bool {
        matches!(
            self,
            Self::Split {
                retired_stable_present: true
            }
        )
    }
}

pub(super) struct TranslatedConfig {
    pub(super) config: BlocklistConfig,
    /// Stable paths the downloader publishes the selected lists under.
    pub(super) selected_base_paths: Vec<PathBuf>,
    pub(super) full_tif_generation: FullTifGeneration,
    pub(super) retired_full_tif_path: Option<PathBuf>,
}

/// Translates macdns settings into the generic runtime config.
///
/// The stable pointer directory scheme is `{identifier}_{url_file_stem}.db`,
/// where `url_file_stem` is what `CategoryLevel::toLevelString` persists as
/// the `level` field in blocklist_settings.json. When that directory contains
/// `.current`, the live LMDB path is resolved from the pointer so reloads can
/// open a content-versioned env without colliding with the previous mmap.
///
/// The tag is the identifier only, with no level suffix. It must equal what
/// the App decodes from lookup history with `BlocklistCategory.fromIdentifier`.
pub fn translate(
    settings: &MacdnsBlocklistSettings,
    blocklists_dir: &Path,
) -> Result<BlocklistConfig> {
    Ok(translate_with_generation(settings, blocklists_dir)?.config)
}

pub(super) fn translate_with_generation(
    settings: &MacdnsBlocklistSettings,
    blocklists_dir: &Path,
) -> Result<TranslatedConfig> {
    let mut blocklists = Vec::new();
    if !settings.enabled {
        return Ok(TranslatedConfig {
            config: BlocklistConfig {
                enabled: false,
                blocklists,
            },
            selected_base_paths: Vec::new(),
            full_tif_generation: FullTifGeneration::NotSelected,
            retired_full_tif_path: None,
        });
    }

    let effective_dir = effective_blocklists_dir(settings, blocklists_dir)?;
    let mut selected_base_paths = Vec::new();
    let mut full_tif_generation = FullTifGeneration::NotSelected;
    let mut retired_full_tif_path = None;

    for cat in &settings.categories {
        if !cat.enabled {
            continue;
        }
        // Parse through the BlockAction deserializer so this accepts exactly
        // the strings the runtime config accepts.
        let action: BlockAction =
            serde_json::from_value(serde_json::Value::String(cat.action.clone())).map_err(|e| {
                BlocklistError::Config(format!(
                    "invalid action '{}' in category '{}': {}",
                    cat.action, cat.identifier, e
                ))
            })?;

        if cat.identifier == "malware_security" && cat.level == "tif" {
            // The downloader only fetches the split generation.
            selected_base_paths.extend(
                ["fake", "tif-1", "tif-2"]
                    .map(|stem| base_db_path(&effective_dir, &cat.identifier, stem)),
            );
            let fake_path = resolve_db_path(&effective_dir, &cat.identifier, "fake")?;
            blocklists.push(BlocklistEntry {
                name: cat.name.clone(),
                tag: cat.identifier.clone(),
                db_path: fake_path,
                action,
            });

            let (paths, generation) = resolve_full_tif_generation(&effective_dir)?;
            full_tif_generation = generation;
            if generation.migration_pending() {
                retired_full_tif_path = Some(effective_dir.join("malware_security_tif.db"));
            }
            for db_path in paths {
                blocklists.push(BlocklistEntry {
                    name: cat.name.clone(),
                    tag: cat.identifier.clone(),
                    db_path,
                    action,
                });
            }
            continue;
        }

        for stem in db_stems_for_selection(&cat.identifier, &cat.level) {
            selected_base_paths.push(base_db_path(&effective_dir, &cat.identifier, &stem));
            let db_path = resolve_db_path(&effective_dir, &cat.identifier, &stem)?;
            blocklists.push(BlocklistEntry {
                name: cat.name.clone(),
                tag: cat.identifier.clone(),
                db_path,
                action,
            });
        }
    }

    Ok(TranslatedConfig {
        config: BlocklistConfig {
            enabled: settings.enabled,
            blocklists,
        },
        selected_base_paths,
        full_tif_generation,
        retired_full_tif_path,
    })
}

fn base_db_path(effective_dir: &Path, identifier: &str, stem: &str) -> PathBuf {
    effective_dir.join(format!("{identifier}_{stem}.db"))
}

fn resolve_db_path(effective_dir: &Path, identifier: &str, stem: &str) -> Result<PathBuf> {
    let base_path = base_db_path(effective_dir, identifier, stem);
    resolve_current_db_path(&base_path).map_err(|error| {
        BlocklistError::Config(format!(
            "enabled category '{}' level '{}' has invalid db '{}': {}",
            identifier,
            stem,
            base_path.display(),
            error
        ))
    })
}

fn resolve_full_tif_generation(effective_dir: &Path) -> Result<(Vec<PathBuf>, FullTifGeneration)> {
    let legacy_base = effective_dir.join("malware_security_tif.db");
    let part1_base = effective_dir.join("malware_security_tif-1.db");
    let part2_base = effective_dir.join("malware_security_tif-2.db");
    let retired_stable_present = legacy_base.exists();

    let part1 = resolve_split_part(&part1_base);
    let part2 = resolve_split_part(&part2_base);
    if let (Some(part1), Some(part2)) = (part1, part2) {
        return Ok((
            vec![part1, part2],
            FullTifGeneration::Split {
                retired_stable_present,
            },
        ));
    }

    match resolve_existing_current_db_path(&legacy_base)? {
        Some(legacy) => Ok((vec![legacy], FullTifGeneration::Legacy)),
        None => Ok((Vec::new(), FullTifGeneration::FakeOnly)),
    }
}

fn resolve_split_part(base_path: &Path) -> Option<PathBuf> {
    match resolve_existing_current_db_path(base_path) {
        Ok(Some(path)) => Some(path),
        Ok(None) => {
            log::warn!(
                "Full TIF split part is unavailable: {}",
                base_path.display()
            );
            None
        }
        Err(error) => {
            log::warn!(
                "Full TIF split part is invalid and will not be selected: {}: {}",
                base_path.display(),
                error
            );
            None
        }
    }
}

fn effective_blocklists_dir(
    settings: &MacdnsBlocklistSettings,
    blocklists_dir: &Path,
) -> Result<PathBuf> {
    let raw = settings.db_base_path.trim();
    let candidate = if raw.is_empty() {
        blocklists_dir.to_path_buf()
    } else {
        PathBuf::from(raw)
    };
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        blocklists_dir.join(candidate)
    };
    if contains_parent(&resolved) {
        return Err(BlocklistError::Config(format!(
            "blocklist db_base_path must not contain '..': {}",
            resolved.display()
        )));
    }
    let base = normalize_lexical(blocklists_dir);
    let resolved = normalize_lexical(&resolved);
    if !resolved.starts_with(&base) {
        return Err(BlocklistError::Config(format!(
            "blocklist db_base_path must stay under {}: {}",
            base.display(),
            resolved.display()
        )));
    }
    if let (Ok(base_real), Ok(resolved_real)) = (base.canonicalize(), resolved.canonicalize()) {
        if !resolved_real.starts_with(&base_real) {
            return Err(BlocklistError::Config(format!(
                "blocklist db_base_path resolves outside {}: {}",
                base_real.display(),
                resolved_real.display()
            )));
        }
    }
    Ok(resolved)
}

fn contains_parent(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if !matches!(component, Component::CurDir) {
            out.push(component.as_os_str());
        }
    }
    out
}

fn db_stems_for_selection(identifier: &str, level: &str) -> Vec<String> {
    let stems: &[&str] = match (identifier, level) {
        ("malware_security", "tif.mini") => &["fake", "tif.mini"],
        ("malware_security", "tif.medium") => &["fake", "tif.medium"],
        ("malware_security", "tif") => &["fake", "tif"],
        ("misc", "urlshortener") => &["popupads", "urlshortener"],
        ("misc", "doh") => &["popupads", "urlshortener", "doh"],
        _ => return vec![level.to_string()],
    };
    stems.iter().map(|s| (*s).to_string()).collect()
}

/// The scheduler applies the result via `blocklist::reload_from_config`.
pub fn load_config(settings_path: &Path, blocklists_dir: &Path) -> Result<BlocklistConfig> {
    Ok(load_config_with_generation(settings_path, blocklists_dir)?.config)
}

pub(super) fn load_config_with_generation(
    settings_path: &Path,
    blocklists_dir: &Path,
) -> Result<TranslatedConfig> {
    if let Ok(meta) = std::fs::metadata(settings_path) {
        if meta.len() > MAX_SETTINGS_BYTES {
            return Err(BlocklistError::Config(format!(
                "blocklist_settings.json too large: {} bytes (max {})",
                meta.len(),
                MAX_SETTINGS_BYTES
            )));
        }
    }
    let json = std::fs::read_to_string(settings_path)?;
    let settings: MacdnsBlocklistSettings = serde_json::from_str(&json).map_err(|e| {
        BlocklistError::Config(format!("failed to parse {:?}: {}", settings_path, e))
    })?;
    if settings.categories.len() > MAX_CATEGORIES {
        return Err(BlocklistError::Config(format!(
            "blocklist_settings.json has {} categories (max {})",
            settings.categories.len(),
            MAX_CATEGORIES
        )));
    }
    if settings.version > super::categories::SCHEMA_VERSION {
        log::warn!(
            "blocklist_settings.json version {} is newer than this resolver's schema ({}); \
             unknown fields are silently ignored — verify on-disk shape matches expectations",
            settings.version,
            super::categories::SCHEMA_VERSION,
        );
    }
    translate_with_generation(&settings, blocklists_dir)
}

#[cfg(test)]
mod tests {
    use super::super::categories::MacdnsCategoryConfig;
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn sample_settings() -> MacdnsBlocklistSettings {
        MacdnsBlocklistSettings {
            version: super::super::categories::SCHEMA_VERSION,
            enabled: true,
            db_base_path: "".into(),
            categories: vec![
                MacdnsCategoryConfig {
                    name: "Ads & Tracking Normal".into(),
                    identifier: "ads_tracking".into(),
                    level: "multi".into(),
                    action: "nxdomain".into(),
                    enabled: true,
                },
                MacdnsCategoryConfig {
                    name: "Adult Light".into(),
                    identifier: "adult".into(),
                    level: "nsfw".into(),
                    action: "nxdomain".into(),
                    enabled: false,
                },
                MacdnsCategoryConfig {
                    name: "Malware & Security Pro".into(),
                    identifier: "malware_security".into(),
                    level: "tif.medium".into(),
                    action: "192.168.1.1".into(),
                    enabled: true,
                },
            ],
        }
    }

    fn full_tif_settings(blocklists_dir: &Path) -> MacdnsBlocklistSettings {
        MacdnsBlocklistSettings {
            version: super::super::categories::SCHEMA_VERSION,
            enabled: true,
            db_base_path: blocklists_dir.to_string_lossy().into_owned(),
            categories: vec![MacdnsCategoryConfig {
                name: "Malware & Security Ultimate".into(),
                identifier: "malware_security".into(),
                level: "tif".into(),
                action: "nxdomain".into(),
                enabled: true,
            }],
        }
    }

    fn publish_valid_versioned_db(base_path: &Path, digest: &str) -> PathBuf {
        let versioned_path = crate::lmdb::paths::versioned_db_path(base_path, digest);
        drop(crate::lmdb::BlocklistDb::open_for_write(&versioned_path).unwrap());
        crate::lmdb::paths::publish_current_db_path(base_path, &versioned_path).unwrap();
        versioned_path
    }

    fn full_tif_paths(translated: &TranslatedConfig) -> Vec<PathBuf> {
        translated
            .config
            .blocklists
            .iter()
            .filter(|entry| entry.tag == "malware_security")
            .map(|entry| entry.db_path.clone())
            .collect()
    }

    #[test]
    fn full_tif_uses_legacy_until_both_split_parts_are_valid() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        let legacy = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif.db"),
            "0123456789abcdef0123456789abcdef",
        );
        publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "123456789abcdef0123456789abcdef0",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db"), legacy]
        );
        assert_eq!(translated.full_tif_generation, FullTifGeneration::Legacy);
    }

    #[test]
    fn full_tif_clean_install_with_one_part_uses_fake_only() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "0123456789abcdef0123456789abcdef",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db")]
        );
        assert_eq!(translated.full_tif_generation, FullTifGeneration::FakeOnly);
    }

    #[test]
    fn full_tif_complete_split_excludes_legacy_path() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        let legacy = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let part1 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "123456789abcdef0123456789abcdef0",
        );
        let part2 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-2.db"),
            "23456789abcdef0123456789abcdef01",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();
        let paths = full_tif_paths(&translated);

        assert_eq!(
            paths,
            vec![temp.path().join("malware_security_fake.db"), part1, part2]
        );
        assert!(!paths.contains(&legacy));
        assert_eq!(
            translated.full_tif_generation,
            FullTifGeneration::Split {
                retired_stable_present: true
            }
        );
    }

    #[test]
    fn full_tif_complete_split_without_old_has_no_pending_migration() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        let part1 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let part2 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-2.db"),
            "123456789abcdef0123456789abcdef0",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db"), part1, part2]
        );
        assert_eq!(
            translated.full_tif_generation,
            FullTifGeneration::Split {
                retired_stable_present: false
            }
        );
        assert!(!translated.full_tif_generation.migration_pending());
    }

    #[test]
    fn full_tif_invalid_split_pointer_preserves_valid_legacy() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        let legacy = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let part1 = temp.path().join("malware_security_tif-1.db");
        std::fs::create_dir_all(&part1).unwrap();
        std::fs::write(part1.join(".current"), "missing-version.db").unwrap();

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db"), legacy]
        );
        assert_eq!(translated.full_tif_generation, FullTifGeneration::Legacy);
    }

    #[test]
    fn full_tif_never_returns_legacy_and_split_paths_together() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        let legacy = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let part1 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "123456789abcdef0123456789abcdef0",
        );
        let part2 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-2.db"),
            "23456789abcdef0123456789abcdef01",
        );

        let paths = full_tif_paths(&translate_with_generation(&settings, temp.path()).unwrap());

        assert_eq!(
            paths,
            vec![temp.path().join("malware_security_fake.db"), part1, part2]
        );
        assert!(!paths.contains(&legacy));
    }

    #[test]
    fn full_tif_pointerless_legacy_dir_with_incomplete_split_uses_fake_only() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        std::fs::create_dir_all(temp.path().join("malware_security_tif.db")).unwrap();
        publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "0123456789abcdef0123456789abcdef",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db")]
        );
        assert_eq!(translated.full_tif_generation, FullTifGeneration::FakeOnly);
    }

    #[test]
    fn full_tif_complete_split_allows_invalid_present_legacy() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        std::fs::create_dir_all(temp.path().join("malware_security_tif.db")).unwrap();
        let part1 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-1.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let part2 = publish_valid_versioned_db(
            &temp.path().join("malware_security_tif-2.db"),
            "123456789abcdef0123456789abcdef0",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(
            full_tif_paths(&translated),
            vec![temp.path().join("malware_security_fake.db"), part1, part2]
        );
        assert_eq!(
            translated.full_tif_generation,
            FullTifGeneration::Split {
                retired_stable_present: true
            }
        );
        assert!(translated.full_tif_generation.migration_pending());
    }

    /// The downloader names its reports by these paths, so they decide which
    /// download failures belong to the selection.
    #[test]
    fn selected_base_paths_are_the_stable_paths_of_enabled_categories() {
        let translated = translate_with_generation(&sample_settings(), Path::new("/base")).unwrap();

        assert_eq!(
            translated.selected_base_paths,
            vec![
                PathBuf::from("/base/ads_tracking_multi.db"),
                PathBuf::from("/base/malware_security_fake.db"),
                PathBuf::from("/base/malware_security_tif.medium.db"),
            ]
        );
    }

    #[test]
    fn selected_base_paths_stay_stable_when_a_version_is_published() {
        let temp = TempDir::new().unwrap();
        let mut settings = sample_settings();
        settings.db_base_path = temp.path().to_string_lossy().into_owned();
        let base = temp.path().join("ads_tracking_multi.db");
        let versioned = publish_valid_versioned_db(&base, "0123456789abcdef0123456789abcdef");

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(translated.config.blocklists[0].db_path, versioned);
        assert_eq!(translated.selected_base_paths[0], base);
    }

    #[test]
    fn full_tif_selects_the_split_parts_the_downloader_fetches() {
        let temp = TempDir::new().unwrap();
        let settings = full_tif_settings(temp.path());
        publish_valid_versioned_db(
            &temp.path().join("malware_security_tif.db"),
            "0123456789abcdef0123456789abcdef",
        );

        let translated = translate_with_generation(&settings, temp.path()).unwrap();

        assert_eq!(translated.full_tif_generation, FullTifGeneration::Legacy);
        assert_eq!(
            translated.selected_base_paths,
            vec![
                temp.path().join("malware_security_fake.db"),
                temp.path().join("malware_security_tif-1.db"),
                temp.path().join("malware_security_tif-2.db"),
            ]
        );
    }

    #[test]
    fn translate_expands_enabled_entries() {
        let out = translate(&sample_settings(), Path::new("/base")).unwrap();
        assert!(out.enabled);
        assert_eq!(out.blocklists.len(), 3);
    }

    #[test]
    fn translate_skips_disabled_category() {
        let out = translate(&sample_settings(), Path::new("/base")).unwrap();
        assert!(out.blocklists.iter().all(|e| e.tag != "adult"));
    }

    #[test]
    fn translate_disabled_settings_do_not_touch_db_paths() {
        let mut settings = sample_settings();
        settings.enabled = false;
        settings.db_base_path = "/outside-blocklists".into();

        let out = translate(&settings, Path::new("/base")).unwrap();

        assert!(!out.enabled);
        assert!(out.blocklists.is_empty());
    }

    #[test]
    fn translate_uses_identifier_levelstem_db_filename() {
        let out = translate(&sample_settings(), Path::new("/base")).unwrap();
        let ads = &out.blocklists[0];
        assert_eq!(ads.db_path, PathBuf::from("/base/ads_tracking_multi.db"));
        assert_eq!(ads.tag, "ads_tracking");
        assert_eq!(ads.action, BlockAction::Nxdomain);
    }

    #[test]
    fn translate_accepts_null_action_written_by_the_agent() {
        let mut settings = sample_settings();
        settings.categories[0].action = "null".into();

        let out = translate(&settings, Path::new("/base")).unwrap();

        assert_eq!(out.blocklists[0].action, BlockAction::Null);
    }

    #[test]
    fn translate_treats_pointerless_non_lmdb_base_dir_as_absent() {
        let temp = TempDir::new().unwrap();
        let mut settings = sample_settings();
        settings.db_base_path = temp.path().to_string_lossy().into_owned();

        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();

        let translated = translate(&settings, temp.path()).unwrap();
        let ads = translated
            .blocklists
            .iter()
            .find(|entry| entry.tag == "ads_tracking")
            .unwrap();
        assert_eq!(ads.db_path, base);
    }

    #[test]
    fn translate_malware_with_custom_ip_action() {
        let out = translate(&sample_settings(), Path::new("/base")).unwrap();
        let malware_paths: Vec<_> = out
            .blocklists
            .iter()
            .filter(|e| e.tag == "malware_security")
            .map(|e| e.db_path.clone())
            .collect();
        assert_eq!(
            malware_paths,
            vec![
                PathBuf::from("/base/malware_security_fake.db"),
                PathBuf::from("/base/malware_security_tif.medium.db"),
            ]
        );
        for malware in out
            .blocklists
            .iter()
            .filter(|e| e.tag == "malware_security")
        {
            match malware.action {
                BlockAction::CustomIp(ip) => assert_eq!(ip.to_string(), "192.168.1.1"),
                other => panic!("expected CustomIp, got {:?}", other),
            }
        }
    }

    #[test]
    fn translate_honors_db_base_path_when_present() {
        let mut settings = sample_settings();
        settings.db_base_path = "/base/configured".into();
        let out = translate(&settings, Path::new("/base")).unwrap();
        assert_eq!(
            out.blocklists[0].db_path,
            PathBuf::from("/base/configured/ads_tracking_multi.db")
        );
    }

    #[test]
    fn translate_rejects_db_base_path_outside_blocklists_dir() {
        let mut settings = sample_settings();
        settings.db_base_path = "/configured".into();

        let err = translate(&settings, Path::new("/base")).unwrap_err();
        assert!(format!("{err:?}").contains("must stay under"));
    }

    #[test]
    fn translate_rejects_db_base_path_traversal() {
        let mut settings = sample_settings();
        settings.db_base_path = "../configured".into();

        let err = translate(&settings, Path::new("/base")).unwrap_err();
        assert!(format!("{err:?}").contains("must not contain '..'"));
    }

    #[test]
    fn translate_uses_current_pointer_when_published() {
        let temp = TempDir::new().unwrap();
        let mut settings = sample_settings();
        settings.db_base_path = temp.path().to_string_lossy().into_owned();

        let base = temp.path().join("ads_tracking_multi.db");
        let md5 = "0123456789abcdef0123456789abcdef";
        let versioned = temp.path().join(format!("ads_tracking_multi.{md5}.db"));
        std::fs::create_dir_all(&base).unwrap();
        drop(crate::lmdb::BlocklistDb::open_for_write(&versioned).unwrap());
        std::fs::write(
            base.join(".current"),
            format!("ads_tracking_multi.{md5}.db"),
        )
        .unwrap();

        let out = translate(&settings, temp.path()).unwrap();
        assert_eq!(out.blocklists[0].db_path, versioned);
    }

    #[test]
    fn translate_errors_when_enabled_current_pointer_is_broken() {
        let temp = TempDir::new().unwrap();
        let mut settings = sample_settings();
        settings.db_base_path = temp.path().to_string_lossy().into_owned();

        let broken = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join(".current"), "missing-version.db").unwrap();

        let err = translate(&settings, temp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("invalid db"));
    }

    #[test]
    fn translate_unknown_action_errors() {
        let mut s = sample_settings();
        s.categories[0].action = "not_a_real_action".into();
        let err = translate(&s, Path::new("/base")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("invalid action"));
    }

    #[test]
    fn load_config_rejects_oversized_settings_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("blocklist_settings.json");
        std::fs::write(&path, " ".repeat((MAX_SETTINGS_BYTES as usize) + 1)).unwrap();

        let err = load_config(&path, temp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("too large"));
    }

    #[test]
    fn load_config_rejects_too_many_categories() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("blocklist_settings.json");
        let mut settings = sample_settings();
        settings.db_base_path = temp.path().to_string_lossy().into_owned();
        settings.categories = vec![settings.categories[0].clone(); MAX_CATEGORIES + 1];
        std::fs::write(&path, serde_json::to_string(&settings).unwrap()).unwrap();

        let err = load_config(&path, temp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("categories"));
    }
}
