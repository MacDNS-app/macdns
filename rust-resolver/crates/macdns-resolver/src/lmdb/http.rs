// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{BlocklistError, Result};
use futures::stream::StreamExt;
use log::debug;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Caps a blocklist download so a malicious or corrupted source cannot
/// exhaust memory or disk.
const MAX_RESPONSE_SIZE: u64 = 500 * 1024 * 1024;

// `MACDNS_VERSION` is set by the release build. Other builds fall back to the
// crate version.
const VERSION: &str = match option_env!("MACDNS_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug)]
pub enum DownloadResult {
    NotModified,
    /// Body has been streamed to the temp path supplied by the caller.
    /// `sha256` was computed incrementally during streaming so callers do
    /// not need to re-read the file from disk to fingerprint it.
    Success {
        etag: Option<String>,
        sha256: String,
    },
    Error(String),
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct FileMetadata {
    pub etag: Option<String>,
    pub sha256: Option<String>,
    /// Legacy metadata field kept so existing installs can reuse their current
    /// content-versioned LMDB until the next successful SHA-256 refresh.
    pub md5: Option<String>,
    pub domain_count: Option<usize>,
    /// Candidate held back because its domain count is outside the accepted
    /// range. Recorded without touching `etag`/`sha256`/`domain_count`, so the
    /// next conditional request still revalidates against the published
    /// version and a second identical candidate can confirm it. Absent in
    /// `.info` files written before two-strike acceptance existed.
    #[serde(default)]
    pub pending_sha256: Option<String>,
    #[serde(default)]
    pub pending_domain_count: Option<usize>,
}

impl FileMetadata {
    pub fn content_hash(&self) -> Option<&str> {
        self.sha256.as_deref().or(self.md5.as_deref())
    }

    /// True when `digest` was already held back once, i.e. this refresh is the
    /// second consecutive one producing the identical candidate.
    pub fn confirms_pending(&self, digest: &str) -> bool {
        self.pending_sha256.as_deref() == Some(digest)
    }
}

/// Async HTTP downloader for blocklists. It runs on the resolver's Tokio
/// runtime, with no blocking reqwest and no rayon threads.
pub struct HttpDownloader {
    client: reqwest::Client,
}

impl HttpDownloader {
    pub fn new() -> Result<Self> {
        let user_agent = format!("macdns-resolver/{}", VERSION);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let url = attempt.url();
                let allowed_target = url.scheme() == "https"
                    && matches!(
                        url.host_str(),
                        Some("raw.githubusercontent.com" | "cdn.jsdelivr.net")
                    );
                if attempt.previous().len() > 3 {
                    attempt.error("too many blocklist redirects")
                } else if !allowed_target {
                    attempt.error("blocklist redirect target is not allowed")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|e| BlocklistError::Network(e.to_string()))?;

        Ok(Self { client })
    }

    fn metadata_path(db_dir: &Path) -> std::path::PathBuf {
        db_dir.join(".info")
    }

    pub fn load_metadata(&self, db_path: &Path) -> Result<Option<FileMetadata>> {
        let metadata_path = Self::metadata_path(db_path);

        if !metadata_path.exists() {
            return Ok(None);
        }

        match std::fs::read_to_string(&metadata_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(metadata) => Ok(Some(metadata)),
                Err(e) => {
                    debug!("Failed to parse metadata file: {}", e);
                    Ok(None)
                }
            },
            Err(e) => {
                debug!("Failed to read metadata file: {}", e);
                Ok(None)
            }
        }
    }

    pub fn save_metadata(&self, db_path: &Path, metadata: &FileMetadata) -> Result<()> {
        std::fs::create_dir_all(db_path)?;

        // Atomic write through temp and rename. A crash between truncate and
        // write would otherwise leave `.info` empty or partial. load_metadata
        // then returns None, and the next refresh discards the cached digest
        // and rebuilds the LMDB even when the upstream bytes are unchanged.
        //
        // `with_extension` cannot be used to derive `.info.tmp` because
        // `.info` has no extension (the leading dot is part of the
        // filename, treated as a hidden file). `with_file_name` swaps the
        // whole filename and produces the expected `db_path/.info.tmp`.
        let metadata_path = Self::metadata_path(db_path);
        let tmp_path = metadata_path.with_file_name(".info.tmp");
        let json = serde_json::to_string_pretty(metadata).map_err(std::io::Error::other)?;
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &metadata_path)?;
        super::paths::sync_dir(db_path)?;

        Ok(())
    }

    /// Async download with ETag cache. Callers must `.await` this on the
    /// ambient Tokio runtime.
    ///
    /// Streams the response body directly to `temp_target` while hashing it
    /// incrementally, so a 500 MB upstream blocklist never sits in memory
    /// alongside live resolver traffic. The body is written first to a
    /// `.partial` sibling and renamed into place atomically. A crash
    /// mid-download leaves the partial behind for the next refresh to
    /// overwrite, never a half-written `temp_target`.
    pub async fn download_with_cache(
        &self,
        url: &str,
        db_path: &Path,
        temp_target: &Path,
        force: bool,
    ) -> Result<DownloadResult> {
        let mut request = self.client.get(url);

        if !force {
            if let Some(metadata) = self.load_metadata(db_path)? {
                if let Some(etag) = metadata.etag {
                    request = request.header("If-None-Match", etag);
                }
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| BlocklistError::Network(e.to_string()))?;
        let status = response.status();

        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(DownloadResult::NotModified);
        }

        if !status.is_success() {
            return Ok(DownloadResult::Error(format!("HTTP error: {}", status)));
        }

        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Early abort for servers that declare Content-Length. Chunked
        // responses omit the header, so the authoritative cap is the
        // per-chunk `total` check in the streaming loop below.
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_RESPONSE_SIZE {
                return Err(BlocklistError::Parse(format!(
                    "Response too large: {} bytes (max {} MB)",
                    content_length,
                    MAX_RESPONSE_SIZE / 1024 / 1024
                )));
            }
        }

        if let Some(parent) = temp_target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // `with_extension` replaces only the last extension, so
        // `foo.txt.<generation>.tmp` becomes `foo.txt.<generation>.partial`.
        let partial = temp_target.with_extension("partial");
        let mut file = tokio::fs::File::create(&partial).await?;
        let mut hasher = Context::new(&SHA256);
        let mut total: u64 = 0;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| BlocklistError::Network(e.to_string()))?;
            total = total.saturating_add(chunk.len() as u64);
            if total > MAX_RESPONSE_SIZE {
                drop(file);
                let _ = tokio::fs::remove_file(&partial).await;
                return Err(BlocklistError::Parse(format!(
                    "Response too large: > {} MB",
                    MAX_RESPONSE_SIZE / 1024 / 1024
                )));
            }
            file.write_all(&chunk).await?;
            hasher.update(&chunk);
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&partial, temp_target).await?;
        if let Some(parent) = temp_target.parent() {
            let parent = parent.to_path_buf();
            tokio::task::spawn_blocking(move || super::paths::sync_dir(&parent))
                .await
                .map_err(std::io::Error::other)??;
        }

        let sha256 = hex_digest(hasher.finish().as_ref());
        Ok(DownloadResult::Success { etag, sha256 })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn legacy_info_without_pending_fields_still_parses() {
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("ads_tracking_multi.db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(
            db_path.join(".info"),
            r#"{"etag":"\"abc\"","sha256":"deadbeef","md5":null,"domain_count":1234}"#,
        )
        .unwrap();

        let downloader = HttpDownloader::new().unwrap();
        let metadata = downloader
            .load_metadata(&db_path)
            .unwrap()
            .expect("legacy .info must still parse");

        assert_eq!(metadata.sha256.as_deref(), Some("deadbeef"));
        assert_eq!(metadata.domain_count, Some(1234));
        assert_eq!(metadata.pending_sha256, None);
        assert_eq!(metadata.pending_domain_count, None);
        assert!(!metadata.confirms_pending("deadbeef"));
    }
}
