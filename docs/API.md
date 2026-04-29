# API Documentation

## CLI API

### Commands

```bash
zertree [OPTIONS] --input <FILE>
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | SBOM file path | Required |
| `--mode` | `-m` | Scoring mode (dev/prod) | `dev` |
| `--rules` | `-r` | Custom rules JSON file | None |
| `--output` | `-o` | Output format (json/html) | `text` |
| `--offline` | | Skip CVE fetching | `false` |

### Examples

```bash
# Basic scan
zertree -i sbom.json

# Production mode with HTML report
zertree -i sbom.json -m prod --output html

# Custom rules
zertree -i sbom.json -r ./rules/custom.json
```

## Output Formats

### JSON

```json
{
  "overall_score": 4.2,
  "components": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "score": 2.5,
      "risk_level": "Ok",
      "cves": [],
      "license": "MIT"
    }
  ],
  "summary": {
    "total_components": 247,
    "critical_count": 8,
    "warning_count": 24,
    "ok_count": 215
  }
}
```

### HTML

Self-contained HTML report with styled tables and risk distribution.

## Web UI API

### Event System

Components communicate via Svelte events:

- `nodeSelect` — Fired when a graph node is clicked
- `toggleFilm` — Toggles film mode
- `reset` — Resets to upload screen

### Data Format

The web UI expects SBOM data in CycloneDX JSON format:

```javascript
{
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      name: "package-name",
      version: "1.0.0",
      licenses: [{ license: { id: "MIT" } }],
      // Optional: pre-calculated risk score
      riskScore: 5.5
    }
  ],
  dependencies: [
    {
      ref: "pkg:npm/package@1.0.0",
      dependsOn: ["pkg:npm/other@2.0.0"]
    }
  ]
}
```

## Scoring API

### Risk Calculation

```rust
let scorer = RiskScorer::new(rules);
let report = scorer.analyze(&sbom);
```

### Custom Rules Format

```json
{
  "name": "custom-rules",
  "cve_weight": 0.35,
  "license_weight": 0.20,
  "freshness_weight": 0.25,
  "maintenance_weight": 0.20,
  "blocked_licenses": ["GPL-3.0", "AGPL-3.0"],
  "license_unknown_score": 5.0,
  "max_age_months": 36,
  "min_contributors": 1
}
```

### Weights

All weights must sum to 1.0 (100%). If they don't, they are normalized.

## CVE Fetcher API

### NVD Integration

```rust
let fetcher = CveFetcher::new().await?;
let cves = fetcher.fetch_for_package("lodash", "4.17.21").await?;
```

### Cache

- Location: `./zertree-cache.db`
- Format: SQLite
- TTL: 24 hours
- Schema: `cves (package_name, version, cve_id, severity, cvss_score, fetched_at)`

## GitHub Action API

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `sbom-path` | No | `sbom.json` | Path to SBOM file |
| `mode` | No | `dev` | Scoring mode |
| `fail-on-critical` | No | `true` | Fail if critical found |
| `output-format` | No | `json` | Report format |

### Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to generated report |
| `critical-count` | Number of critical issues |
| `score` | Overall risk score |
