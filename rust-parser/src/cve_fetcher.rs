use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::scorer::CveInfo;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
}

#[derive(Debug, Serialize)]
struct OsvPackage<'a> {
    purl: &'a str,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

pub struct CveFetcher {
    client: reqwest::Client,
    cache: Option<VulnCache>,
}

impl CveFetcher {
    pub fn new(client: reqwest::Client, cache: Option<VulnCache>) -> Self {
        Self { client, cache }
    }

    pub async fn fetch_for_purl(&self, purl: &str) -> Result<Vec<CveInfo>> {
        if let Some(cache) = &self.cache {
            if let Some(cached) = cache.get(purl)? {
                return Ok(cached);
            }
        }

        let body = OsvQuery {
            package: OsvPackage { purl },
        };

        let response = self
            .client
            .post(OSV_QUERY_URL)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("OSV query failed for {}", purl))?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let osv: OsvResponse = response
            .json()
            .await
            .unwrap_or(OsvResponse { vulns: vec![] });
        let cves = osv.vulns.into_iter().map(convert_vuln).collect::<Vec<_>>();

        if let Some(cache) = &self.cache {
            cache.put(purl, &cves)?;
        }

        Ok(cves)
    }
}

fn convert_vuln(v: OsvVuln) -> CveInfo {
    let id = v
        .aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| v.id.clone());

    let description = v
        .summary
        .or(v.details)
        .unwrap_or_else(|| "No description available".to_string());

    let (severity, cvss_score) = extract_severity(&v.severity, v.database_specific.as_ref());

    CveInfo {
        id,
        severity,
        cvss_score,
        description,
    }
}

// Pull severity from OSV. Try database_specific.severity first (GHSA gives
// readable labels), then CVSS v3 numeric score, then UNKNOWN.
fn extract_severity(
    severity: &[OsvSeverity],
    db_specific: Option<&serde_json::Value>,
) -> (String, f64) {
    if let Some(s) = db_specific
        .and_then(|v| v.get("severity"))
        .and_then(|v| v.as_str())
    {
        let label = s.to_uppercase();
        let score = severity_label_to_score(&label);
        return (label, score);
    }

    if let Some(cvss) = severity
        .iter()
        .find(|s| s.severity_type.starts_with("CVSS_V3"))
    {
        if let Some(score) = parse_cvss_score(&cvss.score) {
            return (score_to_label(score), score);
        }
    }

    ("UNKNOWN".to_string(), 0.0)
}

fn severity_label_to_score(label: &str) -> f64 {
    match label {
        "CRITICAL" => 9.5,
        "HIGH" => 7.5,
        "MODERATE" | "MEDIUM" => 5.0,
        "LOW" => 2.5,
        _ => 0.0,
    }
}

fn score_to_label(score: f64) -> String {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s > 0.0 => "LOW",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn parse_cvss_score(s: &str) -> Option<f64> {
    s.rsplit('/').next()?.parse::<f64>().ok()
}

pub struct VulnCache {
    conn: Connection,
}

impl VulnCache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open cache at {}", path.display()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vuln_cache (
                purl       TEXT PRIMARY KEY,
                vulns_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self { conn })
    }

    pub fn get(&self, purl: &str) -> Result<Option<Vec<CveInfo>>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT vulns_json, fetched_at FROM vuln_cache WHERE purl = ?1",
                params![purl],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();

        if let Some((json, fetched_at)) = row {
            if now.saturating_sub(fetched_at as u64) < CACHE_TTL_SECS {
                return Ok(Some(serde_json::from_str(&json)?));
            }
        }
        Ok(None)
    }

    pub fn put(&self, purl: &str, cves: &[CveInfo]) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let json = serde_json::to_string(cves)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vuln_cache (purl, vulns_json, fetched_at) VALUES (?1, ?2, ?3)",
            params![purl, json, now],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_labels_map_to_scores() {
        assert!(severity_label_to_score("CRITICAL") > severity_label_to_score("HIGH"));
        assert!(severity_label_to_score("HIGH") > severity_label_to_score("MEDIUM"));
        assert_eq!(severity_label_to_score("UNKNOWN"), 0.0);
    }

    #[test]
    fn cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let cache = VulnCache::open(&path).unwrap();
        let cves = vec![CveInfo {
            id: "CVE-2024-0001".into(),
            severity: "HIGH".into(),
            cvss_score: 7.5,
            description: "test".into(),
        }];
        cache.put("pkg:npm/test@1.0.0", &cves).unwrap();
        let got = cache.get("pkg:npm/test@1.0.0").unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "CVE-2024-0001");
    }

    #[test]
    fn cache_miss_for_unknown_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let cache = VulnCache::open(&path).unwrap();
        assert!(cache.get("pkg:npm/never@0.0.0").unwrap().is_none());
    }
}
