// Package metadata fetched from public registries: when a version was
// published, and how many versions of the package exist. Used to compute
// freshness and maintenance scores. Returns None for unsupported ecosystems
// or unparseable purls — callers fall back to "unknown" scoring.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const METADATA_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageMetadata {
    pub release_age_days: Option<u64>,
    pub total_versions: Option<usize>,
}

#[derive(Debug)]
struct ParsedPurl {
    ecosystem: String,
    name: String,
    version: String,
}

fn parse_purl(purl: &str) -> Option<ParsedPurl> {
    let rest = purl.strip_prefix("pkg:")?;
    let (ecosystem, after) = rest.split_once('/')?;
    let (name_part, version) = after.split_once('@')?;
    Some(ParsedPurl {
        ecosystem: ecosystem.to_lowercase(),
        // npm scope `pkg:npm/%40scope/name@1.0.0` keeps the slash inside name_part.
        name: urldecode(name_part),
        version: version.to_string(),
    })
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn fetch(
    client: &reqwest::Client,
    cache: Option<&MetadataCache>,
    purl: &str,
) -> Result<Option<PackageMetadata>> {
    if let Some(c) = cache {
        if let Some(md) = c.get(purl)? {
            return Ok(Some(md));
        }
    }

    let parsed = match parse_purl(purl) {
        Some(p) => p,
        None => return Ok(None),
    };

    let result = match parsed.ecosystem.as_str() {
        "npm" => fetch_npm(client, &parsed).await,
        "cargo" => fetch_cargo(client, &parsed).await,
        "pypi" => fetch_pypi(client, &parsed).await,
        _ => return Ok(None),
    };

    // Network errors degrade to "unknown" rather than aborting the whole scan.
    let metadata = result.ok();

    if let (Some(c), Some(md)) = (cache, metadata.as_ref()) {
        c.put(purl, md).ok();
    }

    Ok(metadata)
}

async fn fetch_npm(client: &reqwest::Client, p: &ParsedPurl) -> Result<PackageMetadata> {
    let url = format!("https://registry.npmjs.org/{}", p.name);
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(PackageMetadata::default());
    }
    let body: serde_json::Value = resp.json().await?;
    let time = body.get("time").and_then(|v| v.as_object());
    let release_age_days = time
        .and_then(|t| t.get(&p.version))
        .and_then(|v| v.as_str())
        .and_then(parse_iso8601_age_days);
    let total_versions = body
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|m| m.len());
    Ok(PackageMetadata {
        release_age_days,
        total_versions,
    })
}

async fn fetch_cargo(client: &reqwest::Client, p: &ParsedPurl) -> Result<PackageMetadata> {
    let url = format!("https://crates.io/api/v1/crates/{}", p.name);
    // crates.io requires a meaningful User-Agent or it returns 403.
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(PackageMetadata::default());
    }
    let body: serde_json::Value = resp.json().await?;
    let versions = body.get("versions").and_then(|v| v.as_array());
    let release_age_days = versions
        .and_then(|arr| {
            arr.iter()
                .find(|v| v.get("num").and_then(|n| n.as_str()) == Some(p.version.as_str()))
        })
        .and_then(|v| v.get("created_at").and_then(|s| s.as_str()))
        .and_then(parse_iso8601_age_days);
    let total_versions = versions.map(|a| a.len());
    Ok(PackageMetadata {
        release_age_days,
        total_versions,
    })
}

async fn fetch_pypi(client: &reqwest::Client, p: &ParsedPurl) -> Result<PackageMetadata> {
    let url = format!("https://pypi.org/pypi/{}/{}/json", p.name, p.version);
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(PackageMetadata::default());
    }
    let body: serde_json::Value = resp.json().await?;
    let release_age_days = body
        .get("urls")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|u| u.get("upload_time_iso_8601").and_then(|s| s.as_str()))
        .and_then(parse_iso8601_age_days);
    let total_versions = body
        .get("releases")
        .and_then(|v| v.as_object())
        .map(|m| m.len());
    Ok(PackageMetadata {
        release_age_days,
        total_versions,
    })
}

// Compute days between an ISO 8601 timestamp and now. We only need the date
// portion (YYYY-MM-DD prefix) — full timezone math is overkill for "how old
// is this package in days". Returns None if the prefix isn't parseable.
fn parse_iso8601_age_days(s: &str) -> Option<u64> {
    let date = s.get(..10)?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    let release_days = days_since_epoch(y, m, d)?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let now_days = now_secs / 86_400;
    Some((now_days as i64 - release_days).max(0) as u64)
}

// Days since 1970-01-01 for a given Gregorian date. Howard Hinnant's
// civil-from-days algorithm, inverted. Returns None for invalid dates.
fn days_since_epoch(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe as i64 * 365 + yoe as i64 / 4 - yoe as i64 / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

pub fn build_client() -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!(
            "ZertTree/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/Zertannax/Zertree)"
        ))
        .build()?;
    Ok(client)
}

pub struct MetadataCache {
    conn: Connection,
}

impl MetadataCache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open metadata cache at {}", path.display()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata_cache (
                purl          TEXT PRIMARY KEY,
                metadata_json TEXT NOT NULL,
                fetched_at    INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self { conn })
    }

    pub fn get(&self, purl: &str) -> Result<Option<PackageMetadata>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT metadata_json, fetched_at FROM metadata_cache WHERE purl = ?1",
                params![purl],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        if let Some((json, fetched_at)) = row {
            if now.saturating_sub(fetched_at as u64) < METADATA_CACHE_TTL_SECS {
                return Ok(Some(serde_json::from_str(&json)?));
            }
        }
        Ok(None)
    }

    pub fn put(&self, purl: &str, md: &PackageMetadata) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let json = serde_json::to_string(md)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata_cache (purl, metadata_json, fetched_at) VALUES (?1, ?2, ?3)",
            params![purl, json, now],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_purl() {
        let p = parse_purl("pkg:npm/lodash@4.17.21").unwrap();
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(p.name, "lodash");
        assert_eq!(p.version, "4.17.21");
    }

    #[test]
    fn parse_scoped_npm_purl() {
        let p = parse_purl("pkg:npm/%40scope/pkg@1.2.3").unwrap();
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(p.name, "@scope/pkg");
        assert_eq!(p.version, "1.2.3");
    }

    #[test]
    fn parse_invalid_purl_returns_none() {
        assert!(parse_purl("not-a-purl").is_none());
        assert!(parse_purl("pkg:npm/no-version").is_none());
    }

    #[test]
    fn epoch_anchor_is_zero() {
        assert_eq!(days_since_epoch(1970, 1, 1), Some(0));
    }

    #[test]
    fn known_dates_round_trip() {
        // 2000-01-01 is 30 years * 365 + 7 leap days = 10957 days after epoch.
        assert_eq!(days_since_epoch(2000, 1, 1), Some(10957));
        // 2024-01-01 is 19723 days after epoch.
        assert_eq!(days_since_epoch(2024, 1, 1), Some(19723));
    }

    #[test]
    fn parse_iso8601_age_handles_t_separator() {
        // We don't assert a specific number — just that parsing succeeds and
        // produces something. This guards the prefix-extraction logic.
        let age = parse_iso8601_age_days("2020-06-15T12:34:56Z");
        assert!(age.is_some());
    }

    #[test]
    fn metadata_cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::open(&dir.path().join("meta.db")).unwrap();
        let md = PackageMetadata {
            release_age_days: Some(42),
            total_versions: Some(99),
        };
        cache.put("pkg:npm/example@1.0.0", &md).unwrap();
        let got = cache.get("pkg:npm/example@1.0.0").unwrap().unwrap();
        assert_eq!(got.release_age_days, Some(42));
        assert_eq!(got.total_versions, Some(99));
    }
}
