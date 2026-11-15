// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

pub mod allowlist;
pub mod config;
pub mod db;
pub mod domain;
pub mod http;
pub mod parser;
pub(crate) mod paths;

pub use allowlist::AllowlistDb;
pub use config::{BlockAction, BlockMatch, BlocklistConfig, BlocklistEntry};
pub use db::{BlocklistDb, MultiCategoryDb};
pub use domain::DomainName;
pub use http::{DownloadResult, FileMetadata, HttpDownloader};
pub use parser::DomainListParser;

/// `Network` is a string instead of `#[from] reqwest::Error` because the
/// inline downloader (see `blocklist_scheduler::downloader`) normalises every
/// reqwest error into a string before surfacing it through this type.
#[derive(Debug, thiserror::Error)]
pub enum BlocklistError {
    #[error("Database error: {0}")]
    Database(#[from] heed::Error),
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, BlocklistError>;
