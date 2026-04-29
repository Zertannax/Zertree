use serde::{Deserialize, Serialize};
use crate::parser::{Sbom, Component};
use crate::rules::RuleSet;

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
    pub score: f64,
    pub risk_level: RiskLevel,
    pub cves: Vec<CveInfo>,
    pub license: Option<String>,
    pub license_risk: f64,
    pub freshness_score: f64,
    pub maintenance_score: f64,
    pub dependencies_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    Warning,
    Ok,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 8.0 {
            RiskLevel::Critical
        } else if score >= 4.0 {
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

    pub fn add_cves(&mut self, package_name: &str, cves: Vec<CveInfo>) {
        self.cve_cache.insert(package_name.to_string(), cves);
    }

    pub fn analyze(&self, sbom: &Sbom) -> RiskReport {
        let mut components: Vec<ComponentRisk> = Vec::new();
        let mut total_cves = 0;

        for component in &sbom.components {
            let cves = self.cve_cache.get(&component.name).cloned().unwrap_or_default();
            total_cves += cves.len();

            let cve_score = self.calculate_cve_score(&cves);
            let license_risk = self.calculate_license_risk(component);
            let freshness_score = self.calculate_freshness_score(component);
            let maintenance_score = self.calculate_maintenance_score(component);

            let score = 
                cve_score * self.rules.cve_weight +
                license_risk * self.rules.license_weight +
                freshness_score * self.rules.freshness_weight +
                maintenance_score * self.rules.maintenance_weight;

            let deps_count = sbom.dependencies.iter()
                .filter(|d| d.reference.contains(&component.name))
                .count();

            components.push(ComponentRisk {
                name: component.name.clone(),
                version: component.version.clone(),
                score: score.min(10.0),
                risk_level: RiskLevel::from_score(score),
                cves,
                license: self.get_license(component),
                license_risk,
                freshness_score,
                maintenance_score,
                dependencies_count: deps_count,
            });
        }

        components.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        let overall_score = if components.is_empty() {
            0.0
        } else {
            components.iter().map(|c| c.score).sum::<f64>() / components.len() as f64
        };

        let critical = components.iter().filter(|c| matches!(c.risk_level, RiskLevel::Critical)).count();
        let warning = components.iter().filter(|c| matches!(c.risk_level, RiskLevel::Warning)).count();
        let ok = components.iter().filter(|c| matches!(c.risk_level, RiskLevel::Ok)).count();

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

    fn calculate_cve_score(&self, cves: &[CveInfo]) -> f64 {
        if cves.is_empty() {
            return 0.0;
        }

        let avg_cvss: f64 = cves.iter().map(|c| c.cvss_score).sum::<f64>() / cves.len() as f64;
        
        let severity_multiplier = match avg_cvss {
            s if s >= 9.0 => 1.5,
            s if s >= 7.0 => 1.2,
            s if s >= 4.0 => 1.0,
            _ => 0.8,
        };

        (avg_cvss / 10.0) * severity_multiplier * 10.0
    }

    fn calculate_license_risk(&self, component: &Component) -> f64 {
        let license = match self.get_license(component) {
            Some(l) => l.to_uppercase(),
            None => return self.rules.license_unknown_score,
        };

        if self.rules.blocked_licenses.iter().any(|bl| license.contains(&bl.to_uppercase())) {
            return 10.0;
        }

        if license.contains("GPL") || license.contains("AGPL") || license.contains("SSPL") {
            return 8.0;
        }

        if license.contains("MIT") || license.contains("APACHE") || license.contains("BSD") || license.contains("ISC") {
            return 0.0;
        }

        self.rules.license_unknown_score
    }

    fn calculate_freshness_score(&self, _component: &Component) -> f64 {
        2.0
    }

    fn calculate_maintenance_score(&self, _component: &Component) -> f64 {
        3.0
    }

    fn get_license(&self, component: &Component) -> Option<String> {
        component.licenses.as_ref()
            ?.first()
            ?.license.id.clone()
            .or_else(|| component.licenses.as_ref()?.first()?.license.name.clone())
    }
}
