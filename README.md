<div align="center">

![ZertTree Logo](branding/logo/logo-animated.svg)

# ZertTree

> **See the forest through the trees**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=%2305D9E8)](https://www.rust-lang.org/)
[![Svelte](https://img.shields.io/badge/Svelte-FF3E00?style=for-the-badge&logo=svelte&logoColor=white)](https://svelte.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-05D9E8?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](.github/workflows/ci.yml)

**Transform your SBOM into an interactive risk map.**
*Stop reading raw JSON. See vulnerabilities and license conflicts at a glance.*

</div>

---

## What is ZertTree?

<div align="center">

![CLI Demo](docs/assets/demo-terminal.svg)

</div>

ZertTree is an **SBOM risk visualizer**. It takes a CycloneDX SBOM, queries
[OSV.dev](https://osv.dev) for known vulnerabilities, scores each component on
CVE severity and license risk, and renders the result as a CLI report, a JSON/HTML
file, or an interactive Svelte + D3.js graph.

> **Status:** early alpha (v0.1.0). The CLI + web UI work end-to-end on CycloneDX
> 1.5 SBOMs. APIs and report formats may change.

---

## Features

| Feature | What it does |
|---------|---------------|
| **CycloneDX 1.5 parser** | Reads CycloneDX JSON SBOMs (component name, version, purl, license). |
| **Vulnerability lookup via OSV.dev** | Queries [OSV.dev](https://osv.dev) by `purl` — no API key needed, accurate per-version. |
| **Registry metadata lookup** | Pulls release date and version count from npm, crates.io and PyPI to score freshness + maintenance. |
| **Local SQLite cache** | Caches OSV responses (24 h) and registry metadata (7 d) at `$XDG_CACHE_HOME/zertree/cache.db`. |
| **4-factor scoring** | CVE severity + license risk + freshness + maintenance, with `dev` / `prod` presets and custom JSON rules. |
| **Concurrent fetches** | Per component, OSV and registry calls run in parallel via `tokio::join!`. |
| **Interactive graph** | Svelte + D3.js force-directed visualization (`web-ui/`). |
| **GitHub Action** | Drop-in Docker action that scans an SBOM and posts a PR comment. |
| **JSON / HTML reports** | `--output json` or `--output html` produces a report file. |

### Not implemented yet

To stay honest, here's what is **not** in this version:

- **PDF export.** Was advertised in the original README, never implemented.
- **`cargo install zertree`.** Not yet on crates.io — build from source for now.
- **`zertannax/zertree-action@v1`.** Not yet published to GitHub Marketplace —
  reference the action by path inside this repo instead.
- **Performance benchmarks.** No "1000+ components/sec" claim is made — none has
  been measured.
- **Ecosystem coverage for freshness/maintenance:** npm, crates.io and PyPI are
  supported. Maven, Go modules, RubyGems, Composer, etc. fall through to a
  neutral score (0).

PRs to fix any of these are welcome.

---

## Quick Start

### CLI (build from source)

```bash
git clone https://github.com/Zertannax/Zertree.git
cd Zertree/rust-parser
cargo build --release
./target/release/zertree --input ../examples/test-sbom-cyclonedx.json
```

Useful flags:

```bash
zertree --input sbom.json --mode prod          # stricter scoring
zertree --input sbom.json --output json        # writes zertree-report.json
zertree --input sbom.json --offline            # skip OSV + registry lookups
zertree --input sbom.json --no-metadata        # skip registry only (keep OSV)
zertree --input sbom.json --no-cache           # bypass the SQLite cache
zertree --input sbom.json --cache /path/to.db  # override cache location
```

### Web UI

```bash
cd web-ui
npm install
npm run dev
# open http://localhost:5173
```

### GitHub Action (from this repo)

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Zertannax/Zertree/github-action@main
        with:
          sbom-path: './sbom.json'
          mode: 'prod'
          fail-on-critical: 'true'
```

---

## Risk Scoring

The final score per component is a weighted sum on a 0–10 scale:

```
score = cve_score        * cve_weight
      + license_risk     * license_weight
      + freshness_risk   * freshness_weight
      + maintenance_risk * maintenance_weight
```

| Factor | Weight (Dev) | Weight (Prod) | Rule |
|--------|:-:|:-:|------|
| CVE severity | 0.50 | 0.60 | Worst CVSS score across all OSV vulns for this `purl`. |
| License risk | 0.30 | 0.20 | MIT/Apache/BSD/ISC = 0; GPL/AGPL/SSPL = 8; blocked = 10; unknown = `license_unknown_score`. |
| Freshness    | 0.10 | 0.10 | Based on the version's release date (npm/crates.io/PyPI): <1 yr = 0; 1–2 yr = 2; 2–3 yr = 5; >3 yr = 8. |
| Maintenance  | 0.10 | 0.10 | Based on total versions on the registry: ≥20 = 0; ≥5 = 2; ≥2 = 5; 1 = 8. |

Unsupported ecosystems (Maven, Go, RubyGems…) return **0** for freshness and
maintenance, so packages we can't look up aren't unfairly penalised.

| Risk level | Score range |
|------------|-------------|
| 🔴 Critical | ≥ 5.0 |
| 🟡 Warning  | 2.5 – 4.99 |
| 🟢 Ok       | < 2.5 |

A single CRITICAL CVE (CVSS ≥ 9.0) is enough to push a component into the
Critical bucket regardless of its license, freshness or maintenance signals.

### Custom rules

```json
{
  "name": "my-company-rules",
  "cve_weight": 0.50,
  "license_weight": 0.20,
  "freshness_weight": 0.15,
  "maintenance_weight": 0.15,
  "blocked_licenses": ["GPL-3.0", "Proprietary"],
  "license_unknown_score": 7.0
}
```

Pass it with `--rules my-rules.json`. `freshness_weight` and
`maintenance_weight` default to 0 if omitted, so v0.1.0 rule files keep
working.

---

## Architecture

```mermaid
graph LR
    A[SBOM JSON] -->|Parse| B[Rust Engine]
    B -->|Score| C[Risk Analysis]
    C -->|Query by purl| D[OSV.dev]
    C -->|Query by purl| R[npm / crates.io / PyPI]
    D -->|Cache 24h| E[SQLite]
    R -->|Cache 7d| E
    C -->|Output| F[Reports]
    F --> G[CLI]
    F --> H[Web UI]
    F --> I[GitHub Action]
```

### Project Structure

```
zertree/
├── rust-parser/     # CLI + parser + scorer + OSV/registry clients (Rust)
├── web-ui/          # Interactive visualization (Svelte + D3.js)
├── github-action/   # Docker-based GitHub Action
├── examples/        # Test SBOMs
└── docs/            # Documentation + assets
```

---

## Design System

| Token | Hex | Usage |
|-------|-----|-------|
| Background | `#0A0A0F` | Main background |
| Cyan | `#05D9E8` | OK / Links |
| Pink | `#FF2A6D` | Critical |
| Yellow | `#F7E018` | Warning |

**Fonts**: Space Grotesk (titles), JetBrains Mono (code), Inter (body)

---

## Testing

```bash
cd rust-parser && cargo test          # 27 unit tests across parser/scorer/registry/cache
cd ../web-ui && npm run build         # smoke build
```

---

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE).
