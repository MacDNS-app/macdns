// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{BlocklistDb, BlocklistError, Result};
use std::io::Write;
use std::path::Component;
use std::path::{Path, PathBuf};

pub(crate) fn versioned_db_path(db_path: &Path, digest: &str) -> PathBuf {
    let file_name = db_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("blocklist.db");
    let stem = file_name.strip_suffix(".db").unwrap_or(file_name);
    db_path.with_file_name(format!("{stem}.{digest}.db"))
}

pub(crate) fn current_db_matches(db_path: &Path, digest: &str) -> bool {
    let expected = versioned_db_path(db_path, digest);
    let Ok(Some(resolved)) = resolve_pointer(db_path) else {
        return false;
    };
    resolved == expected && valid_existing_db_path(&resolved)
}

pub(crate) fn resolve_current_db_path(base_path: &Path) -> Result<PathBuf> {
    Ok(resolve_existing_current_db_path(base_path)?.unwrap_or_else(|| base_path.to_path_buf()))
}

pub(crate) fn resolve_existing_current_db_path(base_path: &Path) -> Result<Option<PathBuf>> {
    if let Some(resolved) = resolve_pointer(base_path)? {
        if !valid_existing_db_path(&resolved) {
            return Err(BlocklistError::Config(format!(
                "blocklist current pointer for {} targets invalid LMDB path {}",
                base_path.display(),
                resolved.display()
            )));
        }
        return Ok(Some(resolved));
    }

    let metadata = match std::fs::symlink_metadata(base_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !valid_existing_db_path(base_path) {
        if metadata.file_type().is_dir() {
            match std::fs::symlink_metadata(base_path.join("data.mdb")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    log::warn!(
                        "blocklist base path {} has no current pointer or data.mdb; treating as absent",
                        base_path.display()
                    );
                    return Ok(None);
                }
                _ => {}
            }
        }
        return Err(BlocklistError::Config(format!(
            "blocklist current pointer is missing and base path is not a valid LMDB env: {}",
            base_path.display()
        )));
    }
    Ok(Some(base_path.to_path_buf()))
}

pub(crate) fn remove_stable_db_and_current_version(base_path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(base_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    if let Some(versioned) = resolve_pointer(base_path)? {
        if versioned.exists() {
            std::fs::remove_dir_all(&versioned)?;
        }
        if base_path.exists() {
            std::fs::remove_dir_all(base_path)?;
        }
    } else {
        if !valid_existing_db_path(base_path) {
            if metadata.file_type().is_dir() && std::fs::read_dir(base_path)?.next().is_none() {
                std::fs::remove_dir(base_path)?;
            } else {
                return Err(BlocklistError::Config(format!(
                    "retired blocklist path is not a valid LMDB env: {}",
                    base_path.display()
                )));
            }
        } else {
            std::fs::remove_dir_all(base_path)?;
        }
    }

    if let Some(parent) = base_path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn valid_existing_db_path(path: &Path) -> bool {
    if !BlocklistDb::existing_env_path(path) {
        return false;
    }

    match BlocklistDb::validate_existing(path) {
        Ok(()) => true,
        Err(BlocklistError::Database(heed::Error::EnvAlreadyOpened)) => true,
        Err(_) => false,
    }
}

pub(crate) fn publish_current_db_path(db_path: &Path, versioned_path: &Path) -> Result<()> {
    std::fs::create_dir_all(db_path)?;
    let file_name = versioned_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| BlocklistError::Config("versioned blocklist path has no filename".into()))?;
    let current = current_pointer_path(db_path);
    let tmp = db_path.join(".current.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(file_name.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &current)?;
    sync_dir(db_path)?;
    Ok(())
}

pub(crate) fn sync_dir(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

fn current_pointer_path(db_path: &Path) -> PathBuf {
    db_path.join(".current")
}

fn resolve_pointer(db_path: &Path) -> Result<Option<PathBuf>> {
    let pointer_path = current_pointer_path(db_path);
    let pointer = match std::fs::read_to_string(&pointer_path) {
        Ok(pointer) => pointer,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let pointer = pointer.trim();
    if pointer.is_empty() {
        return Err(BlocklistError::Config(format!(
            "blocklist current pointer is empty: {}",
            pointer_path.display()
        )));
    }

    validate_pointer_filename(db_path, pointer)?;
    let resolved = if let Some(parent) = db_path.parent() {
        parent.join(pointer)
    } else {
        PathBuf::from(pointer)
    };
    Ok(Some(resolved))
}

fn validate_pointer_filename(db_path: &Path, pointer: &str) -> Result<()> {
    let candidate = Path::new(pointer);
    if candidate
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(BlocklistError::Config(format!(
            "blocklist current pointer must be a filename, got '{}'",
            pointer
        )));
    }
    let base_name = db_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            BlocklistError::Config(format!(
                "blocklist base path has no filename: {}",
                db_path.display()
            ))
        })?;
    let base_stem = base_name.strip_suffix(".db").unwrap_or(base_name);
    let prefix = format!("{base_stem}.");
    let Some(digest) = pointer
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(".db"))
    else {
        return Err(BlocklistError::Config(format!(
            "blocklist current pointer '{}' does not match {}<digest>.db",
            pointer, prefix
        )));
    };
    if !valid_content_digest(digest) {
        return Err(BlocklistError::Config(format!(
            "blocklist current pointer '{}' has invalid digest segment",
            pointer
        )));
    }
    Ok(())
}

fn valid_content_digest(digest: &str) -> bool {
    matches!(digest.len(), 32 | 64) && digest.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const MD5: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn versioned_db_path_keeps_stable_base_separate_from_live_env() {
        let base = Path::new("/tmp/ads_tracking_multi.db");
        assert_eq!(
            versioned_db_path(base, MD5),
            PathBuf::from("/tmp/ads_tracking_multi.0123456789abcdef0123456789abcdef.db")
        );
    }

    #[test]
    fn publish_current_db_path_writes_relative_pointer() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let versioned = temp.path().join(format!("ads_tracking_multi.{digest}.db"));
        BlocklistDb::open_for_write(&versioned).unwrap();

        publish_current_db_path(&base, &versioned).unwrap();

        assert_eq!(
            std::fs::read_to_string(base.join(".current")).unwrap(),
            format!("ads_tracking_multi.{digest}.db")
        );
        assert!(current_db_matches(&base, digest));
    }

    #[test]
    fn current_db_matches_rejects_missing_or_stale_pointer() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();

        assert!(!current_db_matches(&base, MD5));

        std::fs::write(
            base.join(".current"),
            format!("ads_tracking_multi.{MD5}.db"),
        )
        .unwrap();
        assert!(!current_db_matches(&base, MD5));
    }

    #[test]
    fn current_db_matches_rejects_invalid_versioned_lmdb() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let versioned = temp.path().join(format!("ads_tracking_multi.{MD5}.db"));
        std::fs::create_dir_all(&versioned).unwrap();
        std::fs::write(versioned.join("data.mdb"), b"not lmdb").unwrap();
        publish_current_db_path(&base, &versioned).unwrap();

        assert!(!current_db_matches(&base, MD5));
    }

    #[test]
    fn resolve_current_db_path_falls_back_when_pointer_is_missing() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");

        assert_eq!(resolve_current_db_path(&base).unwrap(), base);
    }

    #[test]
    fn resolve_current_db_path_accepts_legacy_lmdb_base_without_pointer() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        BlocklistDb::open_for_write(&base).unwrap();

        assert_eq!(resolve_current_db_path(&base).unwrap(), base);
    }

    #[test]
    fn resolve_current_db_path_falls_back_when_base_dir_is_not_lmdb() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();

        assert_eq!(resolve_current_db_path(&base).unwrap(), base);
    }

    #[test]
    fn resolve_existing_current_db_path_treats_invalid_pointerless_dir_as_absent() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();

        assert_eq!(resolve_existing_current_db_path(&base).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_existing_current_db_path_rebuilds_dangling_current_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();
        symlink(temp.path().join("missing-pointer"), base.join(".current")).unwrap();

        assert_eq!(resolve_existing_current_db_path(&base).unwrap(), None);

        let versioned = versioned_db_path(&base, MD5);
        BlocklistDb::open_for_write(&versioned).unwrap();
        publish_current_db_path(&base, &versioned).unwrap();

        assert_eq!(
            resolve_existing_current_db_path(&base).unwrap(),
            Some(versioned)
        );
    }

    #[test]
    fn resolve_existing_current_db_path_rejects_corrupt_pointerless_lmdb() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("data.mdb"), b"not lmdb").unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[test]
    fn resolve_existing_current_db_path_rejects_invalid_data_mdb_node() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(base.join("data.mdb")).unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[test]
    fn resolve_existing_current_db_path_rejects_pointerless_regular_file() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::write(&base, b"not an lmdb directory").unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_existing_current_db_path_rejects_pointerless_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("invalid-target");
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, &base).unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_existing_current_db_path_rejects_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        symlink(temp.path().join("missing-target"), &base).unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[test]
    fn resolve_current_db_path_errors_when_pointer_target_is_missing() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join(".current"),
            format!("ads_tracking_multi.{MD5}.db"),
        )
        .unwrap();

        assert!(resolve_current_db_path(&base).is_err());
    }

    #[test]
    fn resolve_current_db_path_rejects_pointer_traversal() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join(".current"),
            format!("../ads_tracking_multi.{MD5}.db"),
        )
        .unwrap();

        let err = resolve_current_db_path(&base).unwrap_err();
        assert!(format!("{err:?}").contains("must be a filename"));
    }

    #[test]
    fn resolve_current_db_path_rejects_pointer_for_other_base() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join(".current"), format!("other.{MD5}.db")).unwrap();

        let err = resolve_current_db_path(&base).unwrap_err();
        assert!(format!("{err:?}").contains("does not match"));
    }

    #[test]
    fn resolve_existing_current_db_path_returns_none_when_absent() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif-1.db");

        assert_eq!(resolve_existing_current_db_path(&base).unwrap(), None);
    }

    #[test]
    fn resolve_existing_current_db_path_accepts_valid_legacy_lmdb() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        drop(BlocklistDb::open_for_write(&base).unwrap());

        assert_eq!(resolve_existing_current_db_path(&base).unwrap(), Some(base));
    }

    #[test]
    fn resolve_existing_current_db_path_returns_valid_versioned_target() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif-1.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let versioned = versioned_db_path(&base, digest);
        drop(BlocklistDb::open_for_write(&versioned).unwrap());
        publish_current_db_path(&base, &versioned).unwrap();

        assert_eq!(
            resolve_existing_current_db_path(&base).unwrap(),
            Some(versioned)
        );
    }

    #[test]
    fn resolve_existing_current_db_path_rejects_broken_pointer() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif-1.db");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join(".current"),
            "malware_security_tif-1.deadbeefdeadbeefdeadbeefdeadbeef.db",
        )
        .unwrap();

        assert!(resolve_existing_current_db_path(&base).is_err());
    }

    #[test]
    fn remove_stable_db_and_current_version_removes_pointer_and_target() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let versioned = versioned_db_path(&base, digest);
        drop(BlocklistDb::open_for_write(&versioned).unwrap());
        publish_current_db_path(&base, &versioned).unwrap();

        remove_stable_db_and_current_version(&base).unwrap();

        assert!(!base.exists());
        assert!(!versioned.exists());
        remove_stable_db_and_current_version(&base).unwrap();
    }

    #[test]
    fn remove_stable_db_and_current_version_finishes_partial_retry() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let versioned = versioned_db_path(&base, digest);
        drop(BlocklistDb::open_for_write(&versioned).unwrap());
        publish_current_db_path(&base, &versioned).unwrap();
        std::fs::remove_dir_all(&versioned).unwrap();

        remove_stable_db_and_current_version(&base).unwrap();

        assert!(!base.exists());
    }

    #[test]
    fn remove_stable_db_and_current_version_removes_legacy_lmdb() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        drop(BlocklistDb::open_for_write(&base).unwrap());

        remove_stable_db_and_current_version(&base).unwrap();

        assert!(!base.exists());
    }

    #[test]
    fn remove_stable_db_and_current_version_removes_empty_physical_directory() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        std::fs::create_dir_all(&base).unwrap();

        remove_stable_db_and_current_version(&base).unwrap();

        assert!(!base.exists());
    }

    #[test]
    fn remove_stable_db_and_current_version_preserves_nonempty_invalid_directory() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        let sentinel = base.join("sentinel");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(&sentinel, b"keep").unwrap();

        assert!(remove_stable_db_and_current_version(&base).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    }

    #[test]
    fn remove_stable_db_and_current_version_is_idempotent_when_absent() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");

        remove_stable_db_and_current_version(&base).unwrap();

        assert!(!base.exists());
    }

    #[test]
    fn remove_stable_db_and_current_version_rejects_traversal_pointer() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("malware_security_tif.db");
        let sentinel = temp.path().join("external-sentinel");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&sentinel).unwrap();
        std::fs::write(base.join(".current"), "../external-sentinel").unwrap();

        assert!(remove_stable_db_and_current_version(&base).is_err());
        assert!(sentinel.exists());
    }
}
