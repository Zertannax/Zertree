use crate::parser::{Component, Sbom};
use crate::rules::RuleSet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub overall_score: f64,
    pub components: Vec<ComponentRisk>,
    pub summary: RiskSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRisk {
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub score: f64,
    pub risk_level: RiskLevel,
    pub cves: Vec<CveInfo>,
    pub license: Option<String>,
    pub license_risk: f64,
    pub dependencies_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    Warning,
    Ok,
}

impl RiskLevel {
    // Thresholds are chosen so a max-severity CVE (10.0) alone always lands in
    // Critical even at the lowest cve_weight (0.6 in dev → 6.0). License-only
    // risk caps at 10.0 * license_weight (≤4.0), which correctly stays Warning.
    pub fn from_score(score: f64) -> Self {
        if score >= 6.0 {
            RiskLevel::Critical
        } else if score >= 3.0 {
            RiskLevel::Warning
        } else {
            RiskLevel::Ok
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub id: String,
    pub severity: String,
    pub cvss_score: f64,
    pub description: String,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default)]
    pub is_cisa_kev: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub total_components: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub ok_count: usize,
    pub total_cves: usize,
}

pub struct RiskScorer {
    rules: RuleSet,
    cve_cache: std::collections::HashMap<String, Vec<CveInfo>>,
}

impl RiskScorer {
    pub fn new(rules: RuleSet) -> Self {
        RiskScorer {
            rules,
            cve_cache: std::collections::HashMap::new(),
        }
    }

    pub fn add_cves(&mut self, key: &str, cves: Vec<CveInfo>) {
        self.cve_cache.insert(key.to_string(), cves);
    }

    pub fn analyze(&self, sbom: &Sbom) -> RiskReport {
        let mut components: Vec<ComponentRisk> = Vec::new();
        let mut total_cves = 0;

        for component in &sbom.components {
            let key = component
                .purl
                .clone()
                .unwrap_or_else(|| component.name.clone());
            let cves = self.cve_cache.get(&key).cloned().unwrap_or_default();
            total_cves += cves.len();

            let cve_score = calculate_cve_score(&cves);
            let license_risk = self.calculate_license_risk(component);

            let score =
                cve_score * self.rules.cve_weight + license_risk * self.rules.license_weight;

            let deps_count = sbom
                .dependencies
                .iter()
                .filter(|d| d.reference.contains(&component.name))
                .count();

            components.push(ComponentRisk {
                name: component.name.clone(),
                version: component.version.clone(),
                purl: component.purl.clone(),
                score: score.min(10.0),
                risk_level: RiskLevel::from_score(score),
                cves,
                license: get_license(component),
                license_risk,
                dependencies_count: deps_count,
            });
        }

        components.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let overall_score = if components.is_empty() {
            0.0
        } else {
            components.iter().map(|c| c.score).sum::<f64>() / components.len() as f64
        };

        let critical = components
            .iter()
            .filter(|c| matches!(c.risk_level, RiskLevel::Critical))
            .count();
        let warning = components
            .iter()
            .filter(|c| matches!(c.risk_level, RiskLevel::Warning))
            .count();
        let ok = components
            .iter()
            .filter(|c| matches!(c.risk_level, RiskLevel::Ok))
            .count();

        RiskReport {
            overall_score: overall_score.min(10.0),
            components,
            summary: RiskSummary {
                total_components: sbom.components.len(),
                critical_count: critical,
                warning_count: warning,
                ok_count: ok,
                total_cves,
            },
        }
    }

    fn calculate_license_risk(&self, component: &Component) -> f64 {
        let license = match get_license(component) {
            Some(l) => l.to_uppercase(),
            None => return self.rules.license_unknown_score,
        };

        if self
            .rules
            .blocked_licenses
            .iter()
            .any(|bl| license.contains(&bl.to_uppercase()))
        {
            return 10.0;
        }

        if license.contains("GPL") || license.contains("AGPL") || license.contains("SSPL") {
            return 8.0;
        }

        if license.contains("MIT")
            || license.contains("APACHE")
            || license.contains("BSD")
            || license.contains("ISC")
        {
            return 0.0;
        }

        self.rules.license_unknown_score
    }
}

// Use the worst CVE score enhanced by threat metrics (EPSS and CISA KEV)
fn calculate_cve_score(cves: &[CveInfo]) -> f64 {
    if cves.is_empty() {
        return 0.0;
    }
    cves.iter()
        .map(|c| {
            let mut score = c.cvss_score;
            if let Some(epss) = c.epss_score {
                // Boost score based on exploit likelihood: up to +2.0
                score += epss * 2.0;
            }
            if let Some(true) = c.is_cisa_kev {
                // Boost score by +2.5 if known to be actively exploited
                score += 2.5;
            }
            score.min(10.0)
        })
        .fold(0.0_f64, f64::max)
        .min(10.0)
}

fn get_license(component: &Component) -> Option<String> {
    let licenses = component.licenses.as_ref()?;
    let first = licenses.first()?;
    first
        .license
        .id
        .clone()
        .or_else(|| first.license.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{License, LicenseDetail};
    use crate::rules::{RuleMode, RuleSet};

    fn make_component(name: &str, license_id: Option<&str>) -> Component {
        Component {
            component_type: "library".into(),
            name: name.into(),
            version: "1.0.0".into(),
            purl: Some(format!("pkg:npm/{}@1.0.0", name)),
            licenses: license_id.map(|id| {
                vec![License {
                    license: LicenseDetail {
                        id: Some(id.into()),
                        name: None,
                    },
                }]
            }),
            description: None,
            publisher: None,
            group: None,
        }
    }

    #[test]
    fn empty_cves_score_zero() {
        assert_eq!(calculate_cve_score(&[]), 0.0);
    }

    #[test]
    fn cve_score_uses_worst_severity() {
        let cves = vec![
            CveInfo {
                id: "CVE-1".into(),
                severity: "LOW".into(),
                cvss_score: 2.0,
                description: String::new(),
                epss_score: None,
                is_cisa_kev: None,
            },
            CveInfo {
                id: "CVE-2".into(),
                severity: "CRITICAL".into(),
                cvss_score: 9.5,
                description: String::new(),
                epss_score: None,
                is_cisa_kev: None,
            },
        ];
        assert_eq!(calculate_cve_score(&cves), 9.5);
    }

    #[test]
    fn mit_is_zero_risk() {
        let scorer = RiskScorer::new(RuleSet::default_mode(RuleMode::Prod));
        let comp = make_component("safe", Some("MIT"));
        assert_eq!(scorer.calculate_license_risk(&comp), 0.0);
    }

    #[test]
    fn gpl_is_high_risk() {
        let scorer = RiskScorer::new(RuleSet::default_mode(RuleMode::Dev));
        let comp = make_component("copyleft", Some("GPL-3.0"));
        assert_eq!(scorer.calculate_license_risk(&comp), 8.0);
    }

    #[test]
    fn blocked_license_maxes_risk() {
        let mut rules = RuleSet::default_mode(RuleMode::Dev);
        rules.blocked_licenses = vec!["Proprietary".into()];
        let scorer = RiskScorer::new(rules);
        let comp = make_component("closed", Some("Proprietary"));
        assert_eq!(scorer.calculate_license_risk(&comp), 10.0);
    }

    #[test]
    fn unknown_license_uses_rule_default() {
        let rules = RuleSet::default_mode(RuleMode::Prod);
        let expected = rules.license_unknown_score;
        let scorer = RiskScorer::new(rules);
        let comp = make_component("mystery", None);
        assert_eq!(scorer.calculate_license_risk(&comp), expected);
    }

    #[test]
    fn analyze_reports_critical_for_severe_cve() {
        let mut scorer = RiskScorer::new(RuleSet::default_mode(RuleMode::Prod));
        scorer.add_cves(
            "pkg:npm/danger@1.0.0",
            vec![CveInfo {
                id: "CVE-2099-9999".into(),
                severity: "CRITICAL".into(),
                cvss_score: 10.0,
                description: String::new(),
                epss_score: None,
                is_cisa_kev: None,
            }],
        );
        let sbom = Sbom {
            bom_format: "CycloneDX".into(),
            spec_version: "1.5".into(),
            serial_number: "urn:uuid:1".into(),
            version: 1,
            components: vec![make_component("danger", Some("MIT"))],
            dependencies: vec![],
        };
        let report = scorer.analyze(&sbom);
        assert_eq!(report.summary.critical_count, 1);
        assert!(report.components[0].score >= 6.0);
    }
}
