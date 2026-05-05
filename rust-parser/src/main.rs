use anyhow::Result;
use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

mod cve_fetcher;
mod parser;
mod rules;
mod scorer;

use parser::SbomParser;
use rules::{RuleMode, RuleSet};
use scorer::RiskScorer;

#[derive(Parser)]
#[command(name = "zertree")]
#[command(about = "ZertTree - SBOM Risk Visualizer")]
#[command(version)]
struct Cli {
    #[arg(short, long, help = "Path to SBOM file (JSON, CycloneDX)")]
    input: PathBuf,

    #[arg(short, long, value_enum, default_value = "dev", help = "Scoring mode")]
    mode: RuleMode,

    #[arg(short, long, help = "Custom rules JSON file")]
    rules: Option<PathBuf>,

    #[arg(long, help = "Output format: json, html (text is always printed)")]
    output: Option<String>,

    #[arg(long, help = "Skip vulnerability fetching (offline mode)")]
    offline: bool,

    #[arg(long, help = "Override the SQLite vulnerability cache path")]
    cache: Option<PathBuf>,

    #[arg(long, help = "Disable the SQLite vulnerability cache")]
    no_cache: bool,
}

fn print_logo() {
    println!(
        "{}",
        r#"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     ███████╗███████╗██████╗ ████████╗██████╗ ███████╗      ║
║     ╚══███╔╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝      ║
║       ███╔╝ █████╗  ██████╔╝   ██║   ██████╔╝█████╗        ║
║      ███╔╝  ██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══╝        ║
║     ███████╗███████╗██║  ██║   ██║   ██║  ██║███████╗      ║
║     ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝      ║
║                                                            ║
║              SBOM RISK VISUALIZER                          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"#
        .cyan()
        .bold()
    );
}

fn print_progress(label: &str, current: usize, total: usize) {
    let width = 30;
    let total = total.max(1);
    let filled = (current * width) / total;
    let bar: String = std::iter::repeat_n('█', filled)
        .chain(std::iter::repeat_n('░', width - filled))
        .collect();
    print!("\r{} [{}] {}%", label.cyan(), bar, (current * 100) / total);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn default_cache_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("zertree").join("cache.db");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("zertree")
            .join("cache.db");
    }
    PathBuf::from("zertree-cache.db")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    print_logo();

    let rules = if let Some(rules_path) = cli.rules {
        let content = fs::read_to_string(rules_path)?;
        serde_json::from_str::<RuleSet>(&content)?
    } else {
        RuleSet::default_mode(cli.mode.clone())
    };

    println!(
        "{} {}",
        "🌳".cyan(),
        format!(
            "ZertTree v{} — {:?} Mode",
            env!("CARGO_PKG_VERSION"),
            cli.mode
        )
        .cyan()
        .bold()
    );
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan());
    println!();

    let sbom_content = fs::read_to_string(&cli.input)?;

    println!("{} Parsing SBOM...", "📦".cyan());
    let mut parser = SbomParser::new();
    let sbom = parser.parse(&sbom_content)?;

    println!(
        "{} Components found: {}",
        "✓".green(),
        sbom.components.len().to_string().cyan().bold()
    );
    println!();

    let mut scorer = RiskScorer::new(rules);

    if !cli.offline {
        let cache_path = if cli.no_cache {
            None
        } else {
            Some(cli.cache.clone().unwrap_or_else(default_cache_path))
        };
        if let Some(p) = &cache_path {
            println!("{} Vuln cache: {}", "💾".cyan(), p.display());
        }

        println!("{} Querying OSV.dev for vulnerabilities...", "🔍".cyan());
        let fetcher = cve_fetcher::CveFetcher::new(cache_path).await?;

        let total = sbom.components.len();
        for (i, component) in sbom.components.iter().enumerate() {
            print_progress("Querying OSV", i + 1, total);
            let purl = match component.purl.clone() {
                Some(p) => p,
                None => continue, // OSV needs a purl; skip if we don't have one
            };
            if let Ok(cves) = fetcher.fetch_for_purl(&purl).await {
                if !cves.is_empty() {
                    scorer.add_cves(&purl, cves);
                }
            }
        }
        println!();
        println!();
    }

    println!("{} Analyzing risks...", "⚡".cyan());
    let report = scorer.analyze(&sbom);

    print_report(&report);

    if let Some(output) = cli.output {
        match output.as_str() {
            "json" => {
                let json = serde_json::to_string_pretty(&report)?;
                fs::write("zertree-report.json", json)?;
                println!(
                    "{} {}",
                    "📄".cyan(),
                    "Full report: zertree-report.json".cyan()
                );
            }
            "html" => {
                let html = generate_html_report(&report)?;
                fs::write("zertree-report.html", html)?;
                println!(
                    "{} {}",
                    "📄".cyan(),
                    "Full report: zertree-report.html".cyan()
                );
            }
            other => {
                eprintln!("Unknown output format: {} (expected json or html)", other);
            }
        }
    }

    Ok(())
}

fn print_report(report: &scorer::RiskReport) {
    let total = report.components.len();
    let s = &report.summary;

    println!("┌─────────────────────────────────────────┐");
    println!(
        "│  {}                      │",
        "RISK DISTRIBUTION".cyan().bold()
    );
    println!("│                                         │");
    println!(
        "│  {} {:12} {:20} │",
        "🔴".red(),
        "CRITICAL".red().bold(),
        format!(
            "{} ({}%)",
            s.critical_count,
            (s.critical_count * 100) / total.max(1)
        )
        .red()
    );
    println!(
        "│  {} {:12} {:20} │",
        "🟡".yellow(),
        "WARNING".yellow().bold(),
        format!(
            "{} ({}%)",
            s.warning_count,
            (s.warning_count * 100) / total.max(1)
        )
        .yellow()
    );
    println!(
        "│  {} {:12} {:20} │",
        "🟢".green(),
        "OK".green().bold(),
        format!("{} ({}%)", s.ok_count, (s.ok_count * 100) / total.max(1)).green()
    );
    println!("│                                         │");
    println!(
        "│  {} {:20} │",
        "Overall Score:".cyan(),
        format!("{:.1}/10.0", report.overall_score).cyan().bold()
    );
    println!("└─────────────────────────────────────────┘");
    println!();

    if s.critical_count > 0 {
        println!("{} {}", "⚠️".yellow(), "TOP THREATS:".yellow().bold());
        for (i, comp) in report
            .components
            .iter()
            .filter(|c| matches!(c.risk_level, scorer::RiskLevel::Critical))
            .take(5)
            .enumerate()
        {
            println!(
                "   {} {}@{} → Score: {}",
                i + 1,
                comp.name.cyan(),
                comp.version.cyan(),
                format!("{:.1}", comp.score).red()
            );
            for cve in comp.cves.iter().take(3) {
                println!("      → {} ({})", cve.id.red(), cve.severity.red());
            }
        }
        println!();
    }
}

fn generate_html_report(report: &scorer::RiskReport) -> Result<String> {
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ZertTree Report</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #0A0A0F; color: #E0E0E0; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .stats { display: flex; justify-content: center; gap: 20px; margin: 20px 0; }
        .stat-box { background: #12121F; padding: 15px; border-radius: 4px; min-width: 120px; text-align: center; }
        .critical { color: #FF2A6D; }
        .warning { color: #F7E018; }
        .ok { color: #05D9E8; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1A1A2E; }
        th { color: #05D9E8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌳 ZertTree Report</h1>
    </div>
"#,
    );

    let s = &report.summary;
    html.push_str(&format!(
        r#"
    <div class="stats">
        <div class="stat-box"><div class="critical">CRITICAL</div><div>{}</div></div>
        <div class="stat-box"><div class="warning">WARNING</div><div>{}</div></div>
        <div class="stat-box"><div class="ok">OK</div><div>{}</div></div>
    </div>
"#,
        s.critical_count, s.warning_count, s.ok_count
    ));

    html.push_str(
        r#"
    <table>
        <tr><th>Package</th><th>Version</th><th>Score</th><th>Vulns</th></tr>
"#,
    );

    for comp in &report.components {
        let class = match comp.risk_level {
            scorer::RiskLevel::Critical => "critical",
            scorer::RiskLevel::Warning => "warning",
            scorer::RiskLevel::Ok => "ok",
        };
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{:.1}</td><td>{}</td></tr>\n",
            html_escape(&comp.name),
            html_escape(&comp.version),
            class,
            comp.score,
            comp.cves.len()
        ));
    }

    html.push_str("</table>\n</body>\n</html>");
    Ok(html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
