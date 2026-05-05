use clap::ValueEnum;
use serde::{Deserialize, Serialize};

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
    pub blocked_licenses: Vec<String>,
    pub license_unknown_score: f64,
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
            cve_weight: 0.60,
            license_weight: 0.40,
            blocked_licenses: vec![],
            license_unknown_score: 5.0,
        }
    }

    pub fn prod_default() -> Self {
        RuleSet {
            name: "prod-default".to_string(),
            cve_weight: 0.70,
            license_weight: 0.30,
            blocked_licenses: vec![
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
                "SSPL-1.0".to_string(),
            ],
            license_unknown_score: 8.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_sum_to_one() {
        let dev = RuleSet::dev_default();
        assert!((dev.cve_weight + dev.license_weight - 1.0).abs() < 1e-9);

        let prod = RuleSet::prod_default();
        assert!((prod.cve_weight + prod.license_weight - 1.0).abs() < 1e-9);
    }

    #[test]
    fn prod_blocks_copyleft_by_default() {
        let prod = RuleSet::prod_default();
        assert!(prod.blocked_licenses.iter().any(|l| l.contains("GPL")));
    }

    #[test]
    fn dev_does_not_block_licenses_by_default() {
        let dev = RuleSet::dev_default();
        assert!(dev.blocked_licenses.is_empty());
    }
}
