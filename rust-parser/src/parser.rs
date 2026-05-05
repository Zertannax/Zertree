use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    #[serde(rename = "bomFormat", alias = "bom_format")]
    pub bom_format: String,
    #[serde(rename = "specVersion", alias = "spec_version")]
    pub spec_version: String,
    #[serde(rename = "serialNumber", alias = "serial_number")]
    pub serial_number: String,
    pub version: i32,
    pub components: Vec<Component>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<License>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub license: LicenseDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseDetail {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(
        rename = "dependsOn",
        alias = "depends_on",
        skip_serializing_if = "Option::is_none"
    )]
    pub depends_on: Option<Vec<String>>,
}

pub struct SbomParser;

impl SbomParser {
    pub fn new() -> Self {
        SbomParser
    }

    pub fn parse(&mut self, content: &str) -> Result<Sbom> {
        let sbom: Sbom = serde_json::from_str(content)
            .with_context(|| "Failed to parse SBOM JSON. Ensure it's a valid CycloneDX format.")?;

        Ok(sbom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_cyclonedx() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:12345",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "licenses": [{"license": {"id": "MIT"}}]
                }
            ],
            "dependencies": []
        }"#;

        let mut parser = SbomParser::new();
        let sbom = parser.parse(json).unwrap();

        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "lodash");
        assert_eq!(sbom.components[0].version, "4.17.21");
    }

    #[test]
    fn test_parse_depends_on_camelcase() {
        // Real CycloneDX uses camelCase. We must accept it.
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:1",
            "version": 1,
            "components": [
                {"type": "library", "name": "a", "version": "1.0.0"},
                {"type": "library", "name": "b", "version": "2.0.0"}
            ],
            "dependencies": [
                {"ref": "pkg:npm/a@1.0.0", "dependsOn": ["pkg:npm/b@2.0.0"]}
            ]
        }"#;

        let mut parser = SbomParser::new();
        let sbom = parser.parse(json).unwrap();

        assert_eq!(sbom.dependencies.len(), 1);
        assert_eq!(
            sbom.dependencies[0].depends_on.as_ref().unwrap()[0],
            "pkg:npm/b@2.0.0"
        );
    }

    #[test]
    fn test_parse_missing_dependencies() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:1",
            "version": 1,
            "components": []
        }"#;

        let mut parser = SbomParser::new();
        let sbom = parser.parse(json).unwrap();
        assert!(sbom.dependencies.is_empty());
    }
}
