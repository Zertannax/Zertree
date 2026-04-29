use serde::{Deserialize, Serialize};
use clap::ValueEnum;

#[derive(Debug, Clone, Serialize, Deserialize, ValueEnum)]
pub enum RuleMode {
    Dev,
    Prod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub cve_weight: f64,
    pub license_weight: f64,
    pub freshness_weight: f64,
    pub maintenance_weight: f64,
    pub blocked_licenses: Vec<String>,
    pub license_unknown_score: f64,
    pub max_age_months: i32,
    pub min_contributors: i32,
}

impl RuleSet {
    pub fn default_mode(mode: RuleMode) -> Self {
        match mode {
            RuleMode::Dev => Self::dev_default(),
            RuleMode::Prod => Self::prod_default(),
        }
    }

    pub fn dev_default() -> Self {
        RuleSet {
            name: "dev-default".to_string(),
            cve_weight: 0.35,
            license_weight: 0.20,
            freshness_weight: 0.25,
            maintenance_weight: 0.20,
            blocked_licenses: vec![],
            license_unknown_score: 5.0,
            max_age_months: 36,
            min_contributors: 1,
        }
    }

    pub fn prod_default() -> Self {
        RuleSet {
            name: "prod-default".to_string(),
            cve_weight: 0.50,
            license_weight: 0.30,
            freshness_weight: 0.10,
            maintenance_weight: 0.10,
            blocked_licenses: vec![
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
                "SSPL-1.0".to_string(),
            ],
            license_unknown_score: 8.0,
            max_age_months: 6,
            min_contributors: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_rules() {
        let rules = RuleSet::default_mode(RuleMode::Dev);
        assert_eq!(rules.cve_weight, 0.35);
        assert_eq!(rules.blocked_licenses.len(), 0);
    }

    #[test]
    fn test_prod_rules() {
        let rules = RuleSet::default_mode(RuleMode::Prod);
        assert_eq!(rules.cve_weight, 0.50);
        assert_eq!(rules.blocked_licenses.len(), 3);
    }
}
