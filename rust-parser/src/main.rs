use std::fs;
use std::path::PathBuf;
use clap::{Parser, ValueEnum};
use colored::*;
use anyhow::Result;

mod parser;
mod scorer;
mod cve_fetcher;
mod rules;

use parser::SbomParser;
use scorer::RiskScorer;
use rules::{RuleSet, RuleMode};

#[derive(Parser)]
#[command(name = "zertree")]
#[command(about = "🌳 ZertTree - SBOM Risk Visualizer")]
#[command(version = "0.1.0")]
struct Cli {
    #[arg(short, long, help = "Path to SBOM file (JSON)")]
    input: PathBuf,

    #[arg(short, long, value_enum, default_value = "dev", help = "Scoring mode")]
    mode: RuleMode,

    #[arg(short, long, help = "Custom rules JSON file")]
    rules: Option<PathBuf>,

    #[arg(long, help = "Output format: json, text, html")]
    output: Option<String>,

    #[arg(long, help = "Skip CVE fetching (offline mode)")]
    offline: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Html,
}

fn print_logo() {
    println!("{}", r#"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     ███████╗███████╗██████╗ ████████╗██████╗ ███████╗     ║
║     ╚══███╔╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝     ║
║       ███╔╝ █████╗  ██████╔╝   ██║   ██████╔╝█████╗       ║
║      ███╔╝  ██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══╝       ║
║     ███████╗███████╗██║  ██║   ██║   ██║  ██║███████╗     ║
║     ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝     ║
║                                                            ║
║              🌳  SBOM RISK VISUALIZER  🌳                  ║
║                                                            ║
║     v0.1.0  •  CycloneDX  •  Rust  •  Svelte              ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"#.cyan().bold());
}

fn print_progress(label: &str, current: usize, total: usize) {
    let width = 30;
    let filled = (current * width) / total.max(1);
    let bar = format!("{:<width$}", "█".repeat(filled)).replace(' ', "░");
    print!("\r{} [{:<width$}] {}%", label.cyan(), bar, (current * 100) / total.max(1));
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

    println!("{} {}", "🌳".cyan(), format!("ZertTree v0.1.0 — {:?} Mode", cli.mode).cyan().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan());
    println!();

    let sbom_content = fs::read_to_string(&cli.input)?;
    
    println!("{} Parsing SBOM...", "📦".cyan());
    let mut parser = SbomParser::new();
    let sbom = parser.parse(&sbom_content)?;
    
    println!("{} Components found: {}", "✓".green(), sbom.components.len().to_string().cyan().bold());
    println!();

    let mut scorer = RiskScorer::new(rules);
    
    if !cli.offline {
        println!("{} Fetching CVE data...", "🔍".cyan());
        let cve_fetcher = cve_fetcher::CveFetcher::new().await?;
        
        for (i, component) in sbom.components.iter().enumerate() {
            print_progress("Fetching CVEs", i + 1, sbom.components.len());
            if let Some(cves) = cve_fetcher.fetch_for_package(&component.name, &component.version).await.ok() {
                scorer.add_cves(&component.name, cves);
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
                println!("{} {}", "📄".cyan(), "Full report: zertree-report.json".cyan());
            }
            "html" => {
                let html = generate_html_report(&report)?;
                fs::write("zertree-report.html", html)?;
                println!("{} {}", "📄".cyan(), "Full report: zertree-report.html".cyan());
            }
            _ => {}
        }
    }
    
    println!();
    println!("{} {}", "🌐".cyan(), "Visualizer: http://localhost:5173".cyan().underline());
    
    Ok(())
}

fn print_report(report: &scorer::RiskReport) {
    let total = report.components.len();
    let critical = report.components.iter().filter(|c| c.score >= 8.0).count();
    let warning = report.components.iter().filter(|c| c.score >= 4.0 && c.score < 8.0).count();
    let ok = total - critical - warning;

    println!("┌─────────────────────────────────────────┐");
    println!("│  {}                      │", "RISK DISTRIBUTION".cyan().bold());
    println!("│                                         │");
    println!("│  {} {:12} {:20} │", "🔴".red(), "CRITICAL".red().bold(), format!("{} ({}%)", critical, (critical * 100) / total.max(1)).red());
    println!("│  {} {:12} {:20} │", "🟡".yellow(), "WARNING".yellow().bold(), format!("{} ({}%)", warning, (warning * 100) / total.max(1)).yellow());
    println!("│  {} {:12} {:20} │", "🟢".green(), "OK".green().bold(), format!("{} ({}%)", ok, (ok * 100) / total.max(1)).green());
    println!("│                                         │");
    println!("│  {} {:20} │", "Overall Score:".cyan(), format!("{:.1}/10.0", report.overall_score).cyan().bold());
    println!("└─────────────────────────────────────────┘");
    println!();

    if critical > 0 {
        println!("{} {}", "⚠️".yellow(), "TOP THREATS:".yellow().bold());
        for (i, comp) in report.components.iter().filter(|c| c.score >= 8.0).take(5).enumerate() {
            println!("   {} {}@{} → Score: {:.1}", i + 1, comp.name.cyan(), comp.version.cyan(), format!("{:.1}", comp.score).red());
            for cve in &comp.cves {
                println!("      → {} ({})", cve.id.red(), cve.severity.red());
            }
        }
        println!();
    }
}

fn generate_html_report(report: &scorer::RiskReport) -> Result<String> {
    let mut html = String::from(r#"<!DOCTYPE html>
<html>
<head>
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
"#);

    let total = report.components.len();
    let critical = report.components.iter().filter(|c| c.score >= 8.0).count();
    let warning = report.components.iter().filter(|c| c.score >= 4.0 && c.score < 8.0).count();
    let ok = total - critical - warning;

    html.push_str(&format!(r#"
    <div class="stats">
        <div class="stat-box"><div class="critical">🔴 CRITICAL</div><div>{}</div></div>
        <div class="stat-box"><div class="warning">🟡 WARNING</div><div>{}</div></div>
        <div class="stat-box"><div class="ok">🟢 OK</div><div>{}</div></div>
    </div>
"#, critical, warning, ok));

    html.push_str(r#"
    <table>
        <tr><th>Package</th><th>Version</th><th>Score</th><th>CVEs</th></tr>
"#);

    for comp in &report.components {
        let class = if comp.score >= 8.0 { "critical" } else if comp.score >= 4.0 { "warning" } else { "ok" };
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{:.1}</td><td>{}</td></tr>\n",
            comp.name, comp.version, class, comp.score, comp.cves.len()
        ));
    }

    html.push_str("</table>\n</body>\n</html>");
    
    Ok(html)
}
