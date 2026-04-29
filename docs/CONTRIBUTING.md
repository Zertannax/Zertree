# Contributing to ZertTree

Thank you for your interest in contributing! 🌳

## Development Setup

### Prerequisites

- Rust 1.70+
- Node.js 18+
- npm or pnpm

### Clone and Build

```bash
git clone https://github.com/zertannax/zertree.git
cd zertree

# Build Rust CLI
cd rust-parser
cargo build --release

# Build Web UI
cd ../web-ui
npm install
npm run dev
```

## Project Structure

```
rust-parser/src/
├── main.rs          # CLI entry point
├── parser.rs        # SBOM parsing
├── scorer.rs        # Risk scoring
├── cve_fetcher.rs   # NVD API client
└── rules.rs         # Scoring rules

web-ui/src/
├── App.svelte       # Main layout
└── lib/
    ├── Graph.svelte     # D3.js visualization
    ├── Sidebar.svelte   # Node details
    ├── Header.svelte    # Top bar
    └── FilmMode.svelte  # Demo mode
```

## Coding Standards

### Rust

- Follow `rustfmt` formatting
- Run `cargo clippy` before committing
- Add tests for new features
- Use `anyhow` for error handling

### Svelte/JavaScript

- Use 2-space indentation
- Prefer named exports
- Add JSDoc comments for functions
- Keep components under 300 lines

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Commit Messages

Follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Formatting
- `refactor:` Code restructuring
- `test:` Tests
- `chore:` Maintenance

Example: `feat(parser): add SPDX support`

## Testing

### Rust

```bash
cd rust-parser
cargo test
cargo test --release  # Performance tests
```

### Web

```bash
cd web-ui
npm test
npm run build  # Verify build
```

## Reporting Issues

Please include:

- ZertTree version
- OS and version
- SBOM sample (if applicable)
- Steps to reproduce
- Expected vs actual behavior

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Respect differing viewpoints

## Questions?

Open a [Discussion](https://github.com/zertannax/zertree/discussions) or reach out on Twitter [@zertannax](https://twitter.com/zertannax).

Happy coding! 🚀
