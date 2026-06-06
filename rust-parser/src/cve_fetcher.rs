use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::scorer::CveInfo;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_QUERY_URL: &str = "https://api.osv.dev/v1/querybatch";
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
}

#[derive(Debug, Serialize)]
struct OsvPackage<'a> {
    purl: &'a str,
}

#[derive(Debug, Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvResponse>,
}

#[derive(Debug, Deserialize)]
struct CisaKevCatalog {
    vulnerabilities: Vec<CisaKevItem>,
}

#[derive(Debug, Deserialize)]
struct CisaKevItem {
    #[serde(rename = "cveID")]
    cve_id: String,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssItem>,
}

#[derive(Debug, Deserialize)]
struct EpssItem {
    cve: String,
    epss: String,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
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
    pub async fn new(cache_path: Option<PathBuf>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("ZertTree/", env!("CARGO_PKG_VERSION")))
            .build()?;

        let cache = match cache_path {
            Some(p) => Some(VulnCache::open(&p)?),
            None => None,
        };

        Ok(Self { client, cache })
    }

    async fn enrich_cves(&self, cves: &mut [CveInfo]) -> Result<()> {
        let cve_ids: Vec<String> = cves
            .iter()
            .map(|c| c.id.clone())
            .filter(|id| id.starts_with("CVE-"))
            .collect();

        if cve_ids.is_empty() {
            return Ok(());
        }

        let kev_set = if let Some(cache) = &self.cache {
            if let Ok(Some(cached_kev)) = cache.get_cisa_kev() {
                cached_kev
            } else {
                let fetched_kev = self.fetch_kev_from_api().await.unwrap_or_default();
                let _ = cache.put_cisa_kev(&fetched_kev);
                fetched_kev
            }
        } else {
            self.fetch_kev_from_api().await.unwrap_or_default()
        };

        let epss_map = self.fetch_epss_batch(&cve_ids).await.unwrap_or_default();

        for cve in cves {
            cve.is_cisa_kev = Some(kev_set.contains(&cve.id));
            if let Some(epss) = epss_map.get(&cve.id) {
                cve.epss_score = Some(*epss);
            } else {
                cve.epss_score = Some(0.01);
            }
        }

        Ok(())
    }

    async fn fetch_kev_from_api(&self) -> Result<HashSet<String>> {
        let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        let res = self.client.get(url).send().await?;
        if !res.status().is_success() {
            return Ok(HashSet::new());
        }
        let catalog: CisaKevCatalog = res.json().await?;
        Ok(catalog.vulnerabilities.into_iter().map(|v| v.cve_id).collect())
    }

    async fn fetch_epss_batch(&self, cve_ids: &[String]) -> Result<HashMap<String, f64>> {
        let mut epss_map = HashMap::new();
        for chunk in cve_ids.chunks(100) {
            let cves_str = chunk.join(",");
            let url = format!("https://api.first.org/data/v1/epss?cve={}", cves_str);
            let res = self.client.get(&url).send().await?;
            if res.status().is_success() {
                if let Ok(resp) = res.json::<EpssResponse>().await {
                    for item in resp.data {
                        if let Ok(score) = item.epss.parse::<f64>() {
                            epss_map.insert(item.cve, score);
                        }
                    }
                }
            }
        }
        Ok(epss_map)
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
        let mut cves = osv.vulns.into_iter().map(convert_vuln).collect::<Vec<_>>();

        let _ = self.enrich_cves(&mut cves).await;

        if let Some(cache) = &self.cache {
            cache.put(purl, &cves)?;
        }

        Ok(cves)
    }

    pub async fn fetch_for_purls(&self, purls: &[String]) -> Result<HashMap<String, Vec<CveInfo>>> {
        let mut results = HashMap::new();
        let mut misses = Vec::new();

        for purl in purls {
            if let Some(cache) = &self.cache {
                if let Some(cached) = cache.get(purl)? {
                    results.insert(purl.clone(), cached);
                    continue;
                }
            }
            misses.push(purl.clone());
        }

        if misses.is_empty() {
            return Ok(results);
        }

        for chunk in misses.chunks(1000) {
            let queries = chunk
                .iter()
                .map(|purl| OsvQuery {
                    package: OsvPackage { purl },
                })
                .collect::<Vec<_>>();

            let body = OsvBatchQuery { queries };

            let response = self
                .client
                .post(OSV_BATCH_QUERY_URL)
                .json(&body)
                .send()
                .await
                .with_context(|| "OSV batch query failed")?;

            if !response.status().is_success() {
                for purl in chunk {
                    results.insert(purl.clone(), Vec::new());
                }
                continue;
            }

            let batch_resp: OsvBatchResponse = response
                .json()
                .await
                .unwrap_or(OsvBatchResponse { results: vec![] });

            for (i, purl) in chunk.iter().enumerate() {
                let mut cves = if let Some(osv_res) = batch_resp.results.get(i) {
                    osv_res.vulns.iter().cloned().map(convert_vuln).collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                let _ = self.enrich_cves(&mut cves).await;

                if let Some(cache) = &self.cache {
                    cache.put(purl, &cves)?;
                }
                results.insert(purl.clone(), cves);
            }
        }

        Ok(results)
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
        epss_score: None,
        is_cisa_kev: None,
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

struct VulnCache {
    conn: Connection,
}

impl VulnCache {
    fn open(path: &PathBuf) -> Result<Self> {
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

    fn get(&self, purl: &str) -> Result<Option<Vec<CveInfo>>> {
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

    fn put(&self, purl: &str, cves: &[CveInfo]) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let json = serde_json::to_string(cves)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vuln_cache (purl, vulns_json, fetched_at) VALUES (?1, ?2, ?3)",
            params![purl, json, now],
        )?;
        Ok(())
    }

    fn get_cisa_kev(&self) -> Result<Option<HashSet<String>>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT vulns_json, fetched_at FROM vuln_cache WHERE purl = 'cisa_kev_catalog'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();

        if let Some((json, fetched_at)) = row {
            if now.saturating_sub(fetched_at as u64) < CACHE_TTL_SECS {
                let ids: Vec<String> = serde_json::from_str(&json)?;
                return Ok(Some(ids.into_iter().collect()));
            }
        }
        Ok(None)
    }

    fn put_cisa_kev(&self, ids: &HashSet<String>) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let vec_ids: Vec<&String> = ids.iter().collect();
        let json = serde_json::to_string(&vec_ids)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vuln_cache (purl, vulns_json, fetched_at) VALUES ('cisa_kev_catalog', ?1, ?2)",
            params![json, now],
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
            epss_score: None,
            is_cisa_kev: None,
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
