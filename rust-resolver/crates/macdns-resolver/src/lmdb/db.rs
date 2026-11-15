// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{BlockMatch, BlocklistEntry, BlocklistError, DomainName, Result};
use heed::types::{Bytes, Unit};
use heed::{CommitOrAbort, Database, EnvOpenOptions};
use std::path::Path;
use std::sync::Arc;

const BLOCKLIST_DB_NAME: &str = "blocklist";

pub struct BlocklistDb {
    env: heed::Env,
    db: Database<'static, Bytes, Unit>,
}

impl BlocklistDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::require_existing_env(path)?;

        let env = Self::open_env(path)?;
        let rtxn = env.read_txn()?;
        let db = env
            .open_databases_and_commit(rtxn, |opener, rtxn| -> Result<_> {
                let db = opener.open_database::<Bytes, Unit>(rtxn, Some(BLOCKLIST_DB_NAME))?;
                Ok(CommitOrAbort::<_, ()>::Commit(db))
            })?
            .unwrap_commit()
            .ok_or_else(|| {
                BlocklistError::Validation(format!(
                    "Blocklist database '{}' is missing in {}",
                    BLOCKLIST_DB_NAME,
                    path.display()
                ))
            })?;

        Ok(Self { env, db })
    }

    pub fn open_for_write(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;

        let env = Self::open_env(path)?;
        let wtxn = env.write_txn()?;
        let db = env
            .create_databases_and_commit(wtxn, |opener, wtxn| -> Result<_> {
                let db = opener.create_database(wtxn, Some(BLOCKLIST_DB_NAME))?;
                Ok(CommitOrAbort::<_, ()>::Commit(db))
            })?
            .unwrap_commit();

        Ok(Self { env, db })
    }

    pub(crate) fn existing_env_path(path: impl AsRef<Path>) -> bool {
        path.as_ref().join("data.mdb").is_file()
    }

    pub(crate) fn validate_existing(path: impl AsRef<Path>) -> Result<()> {
        Self::open(path).map(|_| ())
    }

    fn require_existing_env(path: &Path) -> Result<()> {
        if !path.is_dir() {
            return Err(BlocklistError::Validation(format!(
                "Blocklist DB path is not a directory: {}",
                path.display()
            )));
        }

        if !Self::existing_env_path(path) {
            return Err(BlocklistError::Validation(format!(
                "Blocklist DB is missing LMDB data file: {}",
                path.display()
            )));
        }

        Ok(())
    }

    fn open_env(path: &Path) -> Result<heed::Env> {
        // SAFETY: heed::EnvOpenOptions::open is unsafe because LMDB mmaps
        // the data file and undefined behaviour occurs if another process
        // writes to the same file with a different page size or while the
        // env is open. We control both ends of every blocklist DB path:
        // the scheduler is the sole writer (via rename-into-place atomic
        // swaps), and the live agent is the sole reader through the
        // process-wide Arc<BlocklistDb>. Page size matches the platform
        // default for every env we open here.
        Ok(unsafe {
            EnvOpenOptions::new()
                .map_size(2 * 1024 * 1024 * 1024)
                .max_dbs(1)
                .max_readers(128)
                .open(path)?
        })
    }

    #[cfg(test)]
    pub fn insert(&self, domain: &DomainName) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let key = domain.as_key_bytes();
        self.db.put(&mut wtxn, &key, &())?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn insert_batch(&self, domains: &[DomainName]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        for domain in domains {
            let key = domain.as_key_bytes();
            self.db.put(&mut wtxn, &key, &())?;
        }
        wtxn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn contains(&self, domain: &DomainName) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        let key = domain.as_key_bytes();
        Ok(self.db.get(&rtxn, &key)?.is_some())
    }

    /// Parent-matching lookup on the caller's transaction. Returns the stored
    /// name that matched.
    pub fn check_with_parents_tx(
        &self,
        txn: &heed::RoTxn,
        domain: &DomainName,
    ) -> Result<Option<String>> {
        let labels = domain.labels();

        // Check exact name, then parents from most specific to least
        // specific. Parent fallback stops one short of the bare TLD so a
        // stray `com` entry cannot block `example.com`; exact single-label
        // entries like `intranet` still match when queried directly.
        for i in 0..labels.len() {
            if i > 0 && labels.len() - i == 1 {
                break;
            }
            let parent_domain = labels[i..].join(".");
            let parent = DomainName::new(&parent_domain)?;
            let key = parent.as_key_bytes();

            if self.db.get(txn, &key)?.is_some() {
                return Ok(Some(parent_domain));
            }
        }

        Ok(None)
    }

    pub fn check_with_parents(&self, domain: &DomainName) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        self.check_with_parents_tx(&rtxn, domain)
    }

    #[cfg(test)]
    pub fn count(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        Ok(self.db.len(&rtxn)?)
    }

    /// Fault injection for the quarantine tests. The env is opened with LMDB
    /// thread-local reader slots, so while the returned transaction is alive
    /// every further lookup on this database from the same thread fails with
    /// `MDB_BAD_RSLOT`. That stands in for a category whose env has become
    /// unusable at runtime, with the other categories unaffected.
    #[cfg(test)]
    pub(crate) fn hold_reader(&self) -> Result<heed::RoTxn<'_, heed::WithTls>> {
        Ok(self.env.read_txn()?)
    }
}

struct LoadedBlocklistDb {
    db: Arc<BlocklistDb>,
    entry: BlocklistEntry,
}

pub struct MultiCategoryDb {
    databases: Vec<LoadedBlocklistDb>,
}

impl MultiCategoryDb {
    pub fn new() -> Self {
        Self {
            databases: Vec::new(),
        }
    }

    pub fn from_databases(databases: Vec<(Arc<BlocklistDb>, BlocklistEntry)>) -> Self {
        Self {
            databases: databases
                .into_iter()
                .map(|(db, entry)| LoadedBlocklistDb { db, entry })
                .collect(),
        }
    }

    #[cfg(test)]
    pub fn from_db_vec(databases: Vec<(BlocklistDb, BlocklistEntry)>) -> Self {
        Self {
            databases: databases
                .into_iter()
                .map(|(db, entry)| LoadedBlocklistDb {
                    db: Arc::new(db),
                    entry,
                })
                .collect(),
        }
    }

    /// Checks each category in order, quarantining any whose lookup fails. An
    /// unreadable category is treated as if it held nothing, so the remaining
    /// categories keep filtering and the query still gets an answer.
    ///
    /// This plane fails open on purpose. A blocklist is user-chosen filtering
    /// policy, not an authorization boundary, so a broken database must
    /// degrade filtering and never black-hole DNS. The licensing and
    /// proxy-control planes are the opposite (fail closed) and must not be
    /// modelled on this.
    pub fn check_domain(&self, domain: &DomainName) -> Option<BlockMatch> {
        for loaded in &self.databases {
            match loaded.db.check_with_parents(domain) {
                Ok(Some(matched_rule)) => {
                    return Some(BlockMatch {
                        action: loaded.entry.action,
                        tag: loaded.entry.tag.clone(),
                        matched_rule,
                    })
                }
                Ok(None) => {}
                Err(e) => crate::blocklist::note_filtering_degraded(
                    &format!("blocklist category '{}'", loaded.entry.tag),
                    &e.to_string(),
                ),
            }
        }
        None
    }

    pub fn database_count(&self) -> usize {
        self.databases.len()
    }

    pub fn holds_database(&self, db_path: &Path) -> bool {
        self.databases
            .iter()
            .any(|loaded| loaded.entry.db_path == db_path)
    }
}

impl Default for MultiCategoryDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb::BlockAction;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn entry(name: &str, tag: &str, action: BlockAction) -> BlocklistEntry {
        BlocklistEntry {
            name: name.to_string(),
            tag: tag.to_string(),
            db_path: PathBuf::from("/unused/in/tests"),
            action,
        }
    }

    #[test]
    fn test_insert_and_check() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");

        let db = BlocklistDb::open_for_write(&db_path).unwrap();

        let domain = DomainName::new("example.com").unwrap();
        db.insert(&domain).unwrap();

        assert!(db.contains(&domain).unwrap());
    }

    #[test]
    fn test_read_open_rejects_empty_directory() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("empty.db");
        std::fs::create_dir_all(&db_path).unwrap();

        let result = BlocklistDb::open(&db_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_read_open_existing_database() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");
        let domain = DomainName::new("example.com").unwrap();

        let writer = BlocklistDb::open_for_write(&db_path).unwrap();
        writer.insert(&domain).unwrap();
        drop(writer);

        let reader = BlocklistDb::open(&db_path).unwrap();

        assert!(reader.contains(&domain).unwrap());
    }

    #[test]
    fn test_check_with_parents() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");

        let db = BlocklistDb::open_for_write(&db_path).unwrap();

        let parent = DomainName::new("example.com").unwrap();
        db.insert(&parent).unwrap();

        let subdomain = DomainName::new("www.example.com").unwrap();
        let result = db.check_with_parents(&subdomain).unwrap();

        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_check_with_parents_matches_exact_single_label_only() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");

        let db = BlocklistDb::open_for_write(&db_path).unwrap();
        db.insert(&DomainName::new("intranet").unwrap()).unwrap();
        db.insert(&DomainName::new("com").unwrap()).unwrap();

        let intranet = DomainName::new("intranet").unwrap();
        let result = db.check_with_parents(&intranet).unwrap();
        assert_eq!(result, Some("intranet".to_string()));

        let child_of_tld = DomainName::new("example.com").unwrap();
        let result = db.check_with_parents(&child_of_tld).unwrap();
        assert!(result.is_none(), "bare TLD must not match child domains");
    }

    #[test]
    fn test_batch_insert() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");

        let db = BlocklistDb::open_for_write(&db_path).unwrap();

        let domains: Vec<DomainName> = vec![
            DomainName::new("example.com").unwrap(),
            DomainName::new("test.com").unwrap(),
            DomainName::new("example.org").unwrap(),
        ];

        db.insert_batch(&domains).unwrap();

        assert_eq!(db.count().unwrap(), 3);
    }

    #[test]
    fn test_multi_category() {
        let temp = TempDir::new().unwrap();

        let db1 = BlocklistDb::open_for_write(temp.path().join("ads.db")).unwrap();
        db1.insert(&DomainName::new("ads.example.com").unwrap())
            .unwrap();

        let db2 = BlocklistDb::open_for_write(temp.path().join("malware.db")).unwrap();
        db2.insert(&DomainName::new("malware.example.com").unwrap())
            .unwrap();

        let multi = MultiCategoryDb::from_db_vec(vec![
            (db1, entry("Ads", "ads", BlockAction::Nxdomain)),
            (db2, entry("Malware", "malware", BlockAction::Localhost)),
        ]);

        let result = multi.check_domain(&DomainName::new("malware.example.com").unwrap());
        assert_eq!(
            result.as_ref().map(|m| m.action),
            Some(BlockAction::Localhost)
        );
        assert_eq!(result.as_ref().map(|m| m.tag.as_str()), Some("malware"));
    }

    #[test]
    fn test_parallel_search_determinism() {
        let temp = TempDir::new().unwrap();

        let db1 = BlocklistDb::open_for_write(temp.path().join("ads.db")).unwrap();
        db1.insert(&DomainName::new("ads.example.com").unwrap())
            .unwrap();

        let db2 = BlocklistDb::open_for_write(temp.path().join("malware.db")).unwrap();
        db2.insert(&DomainName::new("malware.example.com").unwrap())
            .unwrap();

        let db3 = BlocklistDb::open_for_write(temp.path().join("tracking.db")).unwrap();
        db3.insert(&DomainName::new("tracker.example.com").unwrap())
            .unwrap();

        let multi = MultiCategoryDb::from_db_vec(vec![
            (db1, entry("Ads", "ads", BlockAction::Nxdomain)),
            (db2, entry("Malware", "malware", BlockAction::Localhost)),
            (db3, entry("Tracking", "tracking", BlockAction::Nxdomain)),
        ]);

        for _ in 0..10 {
            let result = multi.check_domain(&DomainName::new("ads.example.com").unwrap());
            assert!(result.is_some());
            assert_eq!(result.as_ref().map(|m| m.tag.as_str()), Some("ads"));

            let result = multi.check_domain(&DomainName::new("malware.example.com").unwrap());
            assert!(result.is_some());
            assert_eq!(result.as_ref().map(|m| m.tag.as_str()), Some("malware"));

            let result = multi.check_domain(&DomainName::new("tracker.example.com").unwrap());
            assert!(result.is_some());
            assert_eq!(result.as_ref().map(|m| m.tag.as_str()), Some("tracking"));

            let result = multi.check_domain(&DomainName::new("safe.example.com").unwrap());
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_transaction_reuse() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("test.db");

        let db = BlocklistDb::open_for_write(&db_path).unwrap();

        let parent = DomainName::new("example.com").unwrap();
        db.insert(&parent).unwrap();

        let rtxn = db.env.read_txn().unwrap();

        let subdomain = DomainName::new("www.example.com").unwrap();
        let result = db.check_with_parents_tx(&rtxn, &subdomain).unwrap();
        assert_eq!(result, Some("example.com".to_string()));

        let deep_subdomain = DomainName::new("deep.www.example.com").unwrap();
        let result = db.check_with_parents_tx(&rtxn, &deep_subdomain).unwrap();
        assert_eq!(result, Some("example.com".to_string()));

        drop(rtxn);

        let result = db.check_with_parents(&subdomain).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }
}
