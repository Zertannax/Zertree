# Architecture

## Overview

ZertTree is split into three main components:

1. **Rust CLI** (`rust-parser/`) — Parsing, scoring, and reporting
2. **Web UI** (`web-ui/`) — Interactive visualization
3. **GitHub Action** (`github-action/`) — CI/CD integration

## Data Flow

```
SBOM JSON → Rust Parser → Risk Scorer → Report
                              ↓
                         NVD API (CVEs)
                              ↓
                         SQLite Cache
                              ↓
                    Web UI / CLI / Action
```

## Rust Parser

### Modules

- `parser.rs` — CycloneDX/SPDX JSON parsing
- `scorer.rs` — Risk calculation engine
- `cve_fetcher.rs` — NVD API client with caching
- `rules.rs` — Configurable scoring rules

### Performance Targets

- Parse 1000 components: < 100ms
- Fetch CVEs (cached): < 10ms per package
- Total analysis (1000 components): < 2s

## Web UI

### Stack

- **Framework**: Svelte 4
- **Visualization**: D3.js (force-directed graph)
- **Animations**: GSAP
- **Build**: Vite

### Components

- `Graph.svelte` — Main D3.js visualization
- `Sidebar.svelte` — Node detail panel
- `Header.svelte` — Stats and controls
- `FilmMode.svelte` — Demo recording overlay

### Performance Targets

- Render 500 nodes: 60fps
- Film mode: smooth camera animation
- Mobile: sidebar becomes bottom sheet

## GitHub Action

### Flow

1. Parse SBOM from repository
2. Run risk analysis
3. Generate report artifact
4. Post PR comment with summary
5. Fail CI if critical issues found

### Inputs

- `sbom-path` — Path to SBOM file
- `mode` — Scoring mode (dev/prod)
- `fail-on-critical` — Boolean
- `output-format` — json/html/pdf

## Security

- No secrets in code
- CVE cache encrypted at rest
- GitHub token scoped to minimum permissions
- No external tracking or analytics
