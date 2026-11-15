// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{BlocklistError, DomainName, Result};
use log::warn;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Caps memory use when a blocklist source is malicious or corrupted.
const MAX_DOMAINS_PER_FILE: usize = 10_000_000;

/// Maximum bytes accepted for a single RPZ line. An upstream file with no
/// newline at all would otherwise grow one allocation to the whole response
/// (capped at 500 MB by `lmdb::http`), so the line buffer is bounded
/// independently of the total response cap.
const MAX_LINE_BYTES: usize = 64 * 1024;

pub struct DomainListParser {
    skip_comments: bool,
}

impl Default for DomainListParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainListParser {
    pub fn new() -> Self {
        Self {
            skip_comments: true,
        }
    }

    pub fn parse_file(&self, path: impl AsRef<Path>) -> Result<Vec<DomainName>> {
        let path = path.as_ref();
        let source = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        self.parse_reader(reader, &source)
    }

    pub fn parse_reader<R: BufRead>(&self, reader: R, source: &str) -> Result<Vec<DomainName>> {
        let mut domains = Vec::new();
        self.parse_reader_in_batches(reader, source, 10_000, |batch| {
            domains.extend_from_slice(batch);
            Ok(())
        })?;
        Ok(domains)
    }

    pub fn parse_reader_in_batches<R, F>(
        &self,
        mut reader: R,
        source: &str,
        batch_size: usize,
        mut on_batch: F,
    ) -> Result<usize>
    where
        R: BufRead,
        F: FnMut(&[DomainName]) -> Result<()>,
    {
        if batch_size == 0 {
            return Err(BlocklistError::Parse(
                "parser batch_size must be greater than zero".into(),
            ));
        }

        let mut batch = Vec::with_capacity(batch_size);
        let mut line_buf: Vec<u8> = Vec::with_capacity(256);
        let mut line_number = 0;
        let mut invalid_domains = 0usize;
        let mut accepted_domains = 0usize;

        while read_bounded_line(&mut reader, &mut line_buf, source, line_number + 1)? {
            line_number += 1;
            let line = std::str::from_utf8(&line_buf).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stream did not contain valid UTF-8",
                )
            })?;

            let Some(raw_domain) = self.extract_domain(line) else {
                continue;
            };
            match DomainName::new(raw_domain) {
                Ok(d) => {
                    if accepted_domains >= MAX_DOMAINS_PER_FILE {
                        return Err(BlocklistError::Parse(format!(
                            "[{}] blocklist exceeds {} domains at line {}; refusing partial publish",
                            source, MAX_DOMAINS_PER_FILE, line_number
                        )));
                    }
                    batch.push(d);
                    accepted_domains += 1;
                    if batch.len() >= batch_size {
                        on_batch(&batch)?;
                        batch.clear();
                    }
                }
                Err(e) => {
                    invalid_domains += 1;
                    if invalid_domains <= 5 {
                        warn!(
                            "[{}] line {}: ignoring invalid domain {:?}: {}",
                            source, line_number, raw_domain, e
                        );
                    }
                }
            }
        }

        if invalid_domains > 5 {
            warn!(
                "[{}] ignored {} invalid domains while parsing blocklist (showing first 5 only)",
                source, invalid_domains
            );
        }

        if !batch.is_empty() {
            on_batch(&batch)?;
        }

        Ok(accepted_domains)
    }

    fn extract_domain<'a>(&self, line: &'a str) -> Option<&'a str> {
        let line = line.trim();

        if line.is_empty() {
            return None;
        }

        if self.skip_comments && line.starts_with(';') {
            return None;
        }

        // Only RPZ block lines count: "domain CNAME ." or "*.domain CNAME .".
        let mut parts = line.split_whitespace();
        let domain = parts.next()?;
        let rtype = parts.next()?;
        let target = parts.next().unwrap_or("");
        if rtype.eq_ignore_ascii_case("CNAME") && target == "." {
            return Some(domain);
        }

        None
    }

    #[cfg(test)]
    fn parse_line(&self, line: &str) -> Option<Result<DomainName>> {
        self.extract_domain(line).map(DomainName::new)
    }
}

/// Reads one `\n`-terminated line into `buf` (newline excluded) and returns
/// `Ok(false)` at end of input. A line longer than `MAX_LINE_BYTES` fails
/// immediately, so the remainder of an unterminated response is never
/// buffered.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    source: &str,
    line_number: usize,
) -> Result<bool> {
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if available.is_empty() {
            return Ok(!buf.is_empty());
        }

        let (chunk_len, consumed, line_complete) =
            match available.iter().position(|byte| *byte == b'\n') {
                Some(newline) => (newline, newline + 1, true),
                None => (available.len(), available.len(), false),
            };
        if buf.len() + chunk_len > MAX_LINE_BYTES {
            return Err(BlocklistError::Parse(format!(
                "[{}] line {} exceeds {} bytes; refusing to buffer the remainder",
                source, line_number, MAX_LINE_BYTES
            )));
        }
        buf.extend_from_slice(&available[..chunk_len]);
        reader.consume(consumed);
        if line_complete {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_simple_list() {
        let list_content = r#"; Blocklist file
example.com CNAME .
test.org CNAME .
ads.example.com CNAME .

; Another comment
tracker.com CNAME .
"#;

        let cursor = Cursor::new(list_content);
        let parser = DomainListParser::new();
        let domains = parser.parse_reader(cursor, "<test>").unwrap();

        assert_eq!(domains.len(), 4);
        assert!(domains.iter().any(|d| d.as_original() == "example.com"));
        assert!(domains.iter().any(|d| d.as_original() == "test.org"));
        assert!(domains.iter().any(|d| d.as_original() == "ads.example.com"));
        assert!(domains.iter().any(|d| d.as_original() == "tracker.com"));
    }

    #[test]
    fn test_parse_line() {
        let parser = DomainListParser::new();

        let rpz_domain = parser.parse_line("example.com CNAME .");
        assert!(rpz_domain.is_some());
        assert_eq!(rpz_domain.unwrap().unwrap().as_original(), "example.com");

        let rpz_wildcard = parser.parse_line("*.example.com CNAME .");
        assert!(rpz_wildcard.is_some());
        assert_eq!(rpz_wildcard.unwrap().unwrap().as_original(), "example.com");

        let comment = parser.parse_line("; comment");
        assert!(comment.is_none());

        let empty = parser.parse_line("");
        assert!(empty.is_none());

        let whitespace = parser.parse_line("   ");
        assert!(whitespace.is_none());

        let soa = parser.parse_line("@ SOA localhost. root.localhost. 123 456 789");
        assert!(soa.is_none());

        let ttl = parser.parse_line("$TTL 300");
        assert!(ttl.is_none());
    }

    #[test]
    fn test_subdomain_blocking() {
        // Storing the base domain blocks its subdomains. db.rs tests that
        // through check_with_parents().
        let parser = DomainListParser::new();

        let domain = parser.parse_line("doubleclick.net CNAME .");
        assert!(domain.is_some());
        let domain = domain.unwrap().unwrap();
        assert_eq!(domain.as_original(), "doubleclick.net");

        // Reversed for LMDB key
        assert_eq!(domain.as_reversed(), "net.doubleclick");
    }

    #[test]
    fn test_parse_rpz_format() {
        let rpz_content = r#"$TTL 300
@ SOA localhost. root.localhost. 1766052660 43200 3600 86400 300
  NS  localhost.
;
; Title: Test RPZ Blocklist
;
smetrics.abbott CNAME .
*.smetrics.abbott CNAME .
fixedfloat.ac CNAME .
*.fixedfloat.ac CNAME .
nugg.ad CNAME .
*.nugg.ad CNAME .
"#;

        let cursor = Cursor::new(rpz_content);
        let parser = DomainListParser::new();
        let domains = parser.parse_reader(cursor, "<test>").unwrap();

        // Should parse 6 domains (base domains, wildcards already stripped)
        assert_eq!(domains.len(), 6);
        assert!(domains.iter().any(|d| d.as_original() == "smetrics.abbott"));
        assert!(domains.iter().any(|d| d.as_original() == "fixedfloat.ac"));
        assert!(domains.iter().any(|d| d.as_original() == "nugg.ad"));
    }

    #[test]
    fn test_invalid_domains_are_ignored() {
        let list_content = r#"valid.example CNAME .
bad_domain CNAME .
another.example CNAME .
"#;

        let cursor = Cursor::new(list_content);
        let parser = DomainListParser::new();
        let domains = parser.parse_reader(cursor, "<test>").unwrap();

        assert_eq!(domains.len(), 2);
        assert!(domains.iter().any(|d| d.as_original() == "valid.example"));
        assert!(domains.iter().any(|d| d.as_original() == "another.example"));
    }

    #[test]
    fn oversized_line_is_rejected_without_batch_callback() {
        let oversized = "a".repeat(MAX_LINE_BYTES + 1);
        let parser = DomainListParser::new();
        let mut batch_calls = 0usize;
        let result =
            parser.parse_reader_in_batches(Cursor::new(oversized), "<test>", 10, |_batch| {
                batch_calls += 1;
                Ok(())
            });

        assert!(
            matches!(result, Err(BlocklistError::Parse(_))),
            "oversized line must be rejected, got {result:?}"
        );
        assert_eq!(batch_calls, 0);
    }

    #[test]
    fn line_at_the_byte_limit_is_still_parsed() {
        let record = "example.com CNAME .";
        let mut line = String::from(record);
        line.push_str(&" ".repeat(MAX_LINE_BYTES - record.len()));
        assert_eq!(line.len(), MAX_LINE_BYTES);
        line.push('\n');

        let parser = DomainListParser::new();
        let domains = parser.parse_reader(Cursor::new(line), "<test>").unwrap();

        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].as_original(), "example.com");
    }

    #[test]
    fn test_parse_reader_streams_batches_without_collecting_full_file() {
        let list_content = r#"one.example CNAME .
two.example CNAME .
three.example CNAME .
four.example CNAME .
five.example CNAME .
"#;

        let cursor = Cursor::new(list_content);
        let parser = DomainListParser::new();
        let mut batches: Vec<Vec<String>> = Vec::new();
        let count = parser
            .parse_reader_in_batches(cursor, "<test>", 2, |batch| {
                batches.push(
                    batch
                        .iter()
                        .map(|domain| domain.as_original().to_string())
                        .collect(),
                );
                Ok(())
            })
            .unwrap();

        assert_eq!(count, 5);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0], ["one.example", "two.example"]);
        assert_eq!(batches[1], ["three.example", "four.example"]);
        assert_eq!(batches[2], ["five.example"]);
    }
}
