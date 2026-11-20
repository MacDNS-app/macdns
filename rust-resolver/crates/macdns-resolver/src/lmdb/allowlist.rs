// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{DomainName, Result};
use heed::types::{Bytes, Unit};
use heed::{CommitOrAbort, Database, EnvOpenOptions};
use std::path::Path;

/// Allowed domains. The allowlist takes precedence over every blocklist.
pub struct AllowlistDb {
    env: heed::Env,
    db: Database<'static, Bytes, Unit>,
}

impl AllowlistDb {
    /// Creates the database if it does not exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;

        // SAFETY: same contract as BlocklistDb::open. Only this process
        // writes to the allowlist LMDB, and UI reads go through the
        // process-wide Arc<AllowlistDb>. Page size matches the platform
        // default.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(100 * 1024 * 1024)
                .max_dbs(1)
                .max_readers(128)
                .open(path)?
        };

        let wtxn = env.write_txn()?;
        let db = env
            .create_databases_and_commit(wtxn, |opener, wtxn| -> Result<_> {
                let db = opener.create_database(wtxn, Some("allowlist"))?;
                Ok(CommitOrAbort::<_, ()>::Commit(db))
            })?
            .unwrap_commit();

        Ok(Self { env, db })
    }

    #[cfg(test)]
    pub fn add_domain(&self, domain: &DomainName) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let key = domain.as_key_bytes();
        self.db.put(&mut wtxn, &key, &())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Replace the entire allowlist in a single write transaction.
    ///
    /// Either every domain is committed or the previous contents remain
    /// untouched; callers never observe a partially applied allowlist.
    pub fn replace_domains(&self, domains: &[DomainName]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.db.clear(&mut wtxn)?;
        for domain in domains {
            let key = domain.as_key_bytes();
            self.db.put(&mut wtxn, &key, &())?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.db.clear(&mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Returns the matching rule when `domain` or one of its parents is
    /// allowed.
    pub fn check_with_parents(&self, domain: &DomainName) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        let labels = domain.labels();

        // Check exact name, then parents from most specific to least
        // specific. Parent fallback stops one short of the bare TLD so an
        // accidental `com` allow entry cannot neutralise every blocklist
        // for that TLD; exact single-label entries like `intranet` still
        // match when queried directly.
        for i in 0..labels.len() {
            if i > 0 && labels.len() - i == 1 {
                break;
            }
            let parent_domain = labels[i..].join(".");
            let parent = DomainName::new(&parent_domain)?;
            let key = parent.as_key_bytes();

            if self.db.get(&rtxn, &key)?.is_some() {
                return Ok(Some(parent_domain));
            }
        }

        Ok(None)
    }

    /// Exact match only, without the parent walk.
    pub fn contains(&self, domain: &DomainName) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        let key = domain.as_key_bytes();
        Ok(self.db.get(&rtxn, &key)?.is_some())
    }

    pub fn list_domains(&self) -> Result<Vec<String>> {
        let rtxn = self.env.read_txn()?;
        let mut domains = Vec::new();

        for result in self.db.iter(&rtxn)? {
            let (key, _) = result?;
            if let Ok(domain_str) = std::str::from_utf8(key) {
                // Keys are stored reversed.
                let original = DomainName::reverse(domain_str);
                domains.push(original);
            }
        }

        Ok(domains)
    }

    pub fn is_empty(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.db.len(&rtxn)? == 0)
    }

    pub fn count(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        Ok(self.db.len(&rtxn)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn replace_domains_commits_full_set_atomically() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("stale.example").unwrap())
            .unwrap();

        let replacement = vec![
            DomainName::new("first.example").unwrap(),
            DomainName::new("second.example").unwrap(),
        ];
        db.replace_domains(&replacement).unwrap();

        assert!(!db
            .contains(&DomainName::new("stale.example").unwrap())
            .unwrap());
        assert!(db
            .contains(&DomainName::new("first.example").unwrap())
            .unwrap());
        assert!(db
            .contains(&DomainName::new("second.example").unwrap())
            .unwrap());
        assert_eq!(db.count().unwrap(), 2);
    }

    #[test]
    fn replace_domains_with_empty_set_clears_allowlist() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("stale.example").unwrap())
            .unwrap();
        db.replace_domains(&[]).unwrap();

        assert!(db.is_empty().unwrap());
    }

    #[test]
    fn test_add_and_contains() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        let domain = DomainName::new("example.com").unwrap();

        assert!(!db.contains(&domain).unwrap());

        db.add_domain(&domain).unwrap();

        assert!(db.contains(&domain).unwrap());
    }

    #[test]
    fn test_clear() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("example.com").unwrap())
            .unwrap();
        db.add_domain(&DomainName::new("example.org").unwrap())
            .unwrap();

        assert_eq!(db.count().unwrap(), 2);

        db.clear().unwrap();
        assert_eq!(db.count().unwrap(), 0);
    }

    #[test]
    fn test_parent_domain_allow() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("example.com").unwrap())
            .unwrap();

        let child = DomainName::new("www.example.com").unwrap();
        assert!(db.check_with_parents(&child).unwrap().is_some());

        let other = DomainName::new("other.com").unwrap();
        assert!(db.check_with_parents(&other).unwrap().is_none());
    }

    #[test]
    fn test_single_label_allow_matches_exact_name_only() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("intranet").unwrap())
            .unwrap();
        db.add_domain(&DomainName::new("com").unwrap()).unwrap();

        let intranet = DomainName::new("intranet").unwrap();
        assert_eq!(
            db.check_with_parents(&intranet).unwrap(),
            Some("intranet".to_string())
        );

        let child_of_tld = DomainName::new("example.com").unwrap();
        assert!(
            db.check_with_parents(&child_of_tld).unwrap().is_none(),
            "bare TLD must not match child domains"
        );
    }

    #[test]
    fn test_list_domains() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        db.add_domain(&DomainName::new("example.com").unwrap())
            .unwrap();
        db.add_domain(&DomainName::new("example.org").unwrap())
            .unwrap();

        let domains = db.list_domains().unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"example.org".to_string()));
    }

    #[test]
    fn test_is_empty() {
        let temp = TempDir::new().unwrap();
        let db = AllowlistDb::open(temp.path()).unwrap();

        assert!(db.is_empty().unwrap());

        db.add_domain(&DomainName::new("example.com").unwrap())
            .unwrap();

        assert!(!db.is_empty().unwrap());
    }
}
