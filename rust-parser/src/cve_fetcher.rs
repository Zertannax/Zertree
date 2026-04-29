use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveResponse {
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve: CveDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDetail {
    pub id: String,
    pub descriptions: Vec<CveDescription>,
    pub metrics: Option<Metrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub cvss_metric_v31: Option<Vec<CvssMetric>>,
    pub cvss_metric_v30: Option<Vec<CvssMetric>>,
    pub cvss_metric_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssMetric {
    pub cvss_data: CvssData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssData {
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssMetricV2 {
    pub cvss_data: CvssDataV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssDataV2 {
    pub base_score: f64,
}

pub struct CveFetcher {
    client: reqwest::Client,
    base_url: String,
}

impl CveFetcher {
    pub async fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ZertTree/0.1.0")
            .build()?;

        Ok(CveFetcher {
            client,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
        })
    }

    pub async fn fetch_for_package(
        &self,
        package_name: &str,
        _version: &str,
    ) -> Result<Vec<crate::scorer::CveInfo>> {
        let keyword = format!("{}", package_name);
        let url = format!(
            "{}?keywordSearch={}&resultsPerPage=20",
            self.base_url,
            urlencoding::encode(&keyword)
        );

        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let cve_response: CveResponse = response.json().await?;
        
        let cves: Vec<crate::scorer::CveInfo> = cve_response.vulnerabilities.into_iter()
            .map(|v| {
                let metrics = v.cve.metrics;
                let (score, severity) = Self::extract_cvss(&metrics);
                
                let description = v.cve.descriptions.iter()
                    .find(|d| d.lang == "en")
                    .map(|d| d.value.clone())
                    .unwrap_or_default();

                crate::scorer::CveInfo {
                    id: v.cve.id,
                    severity,
                    cvss_score: score,
                    description,
                }
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(200)).await;
        
        Ok(cves)
    }

    fn extract_cvss(metrics: &Option<Metrics>) -> (f64, String) {
        let metrics = match metrics {
            Some(m) => m,
            None => return (0.0, "UNKNOWN".to_string()),
        };

        if let Some(v31) = &metrics.cvss_metric_v31 {
            if let Some(first) = v31.first() {
                return (first.cvss_data.base_score, first.cvss_data.base_severity.clone());
            }
        }

        if let Some(v30) = &metrics.cvss_metric_v30 {
            if let Some(first) = v30.first() {
                return (first.cvss_data.base_score, first.cvss_data.base_severity.clone());
            }
        }

        if let Some(v2) = &metrics.cvss_metric_v2 {
            if let Some(first) = v2.first() {
                let severity = if first.cvss_data.base_score >= 7.0 {
                    "HIGH"
                } else if first.cvss_data.base_score >= 4.0 {
                    "MEDIUM"
                } else {
                    "LOW"
                };
                return (first.cvss_data.base_score, severity.to_string());
            }
        }

        (0.0, "UNKNOWN".to_string())
    }
}
