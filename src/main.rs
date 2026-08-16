mod patterns;
mod scanner;
mod git_history;
mod entropy;

use clap::Parser;
use colored::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secretscan-rs")]
#[command(about = "Scanner de segredos expostos em código-fonte")]
struct Args {
    /// Caminho para escanear (arquivo ou diretório)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Padrões de caminho para excluir (substring match)
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Formato de saída: text, json, markdown
    #[arg(long, default_value = "text")]
    output: String,

    /// Arquivo de saída (se omitido, imprime no terminal)
    #[arg(long)]
    out_file: Option<PathBuf>,

    /// Sai com código 1 se encontrar algo >= essa severidade (HIGH ou MEDIUM)
    #[arg(long)]
    fail_on: Option<String>,

    /// Também escaneia o histórico completo do git (todos os commits)
    #[arg(long)]
    git_history: bool,

    /// Ativa deteccao por entropia (fallback para segredos sem padrao
    /// conhecido). Opt-in porque gera mais falso positivo.
    #[arg(long)]
    entropy: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let findings = scanner::scan_path(&args.path, &args.exclude, args.entropy)?;

    let mut findings = findings;
    if args.git_history {
        match git_history::scan_git_history(&args.path) {
            Ok(mut hist_findings) => findings.append(&mut hist_findings),
            Err(e) => eprintln!("Aviso: nao foi possivel escanear historico git: {}", e),
        }
    }

    match args.output.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&findings)?;
            write_output(&json, &args.out_file)?;
        }
        "markdown" => {
            let md = to_markdown(&findings);
            write_output(&md, &args.out_file)?;
        }
        _ => print_text(&findings),
    }

    if findings.is_empty() {
        println!("{}", "Nenhum segredo encontrado.".green());
    } else {
        println!("\n{} {} encontrados", findings.len(), "segredos".bold());
    }

    if let Some(fail_level) = args.fail_on {
        let should_fail = findings.iter().any(|f| match fail_level.to_uppercase().as_str() {
            "HIGH" => f.severity == "HIGH",
            "MEDIUM" => f.severity == "HIGH" || f.severity == "MEDIUM",
            _ => false,
        });
        if should_fail {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_text(findings: &[scanner::Finding]) {
    for f in findings {
        let sev = match f.severity.as_str() {
            "HIGH" => f.severity.red().bold(),
            "MEDIUM" => f.severity.yellow().bold(),
            _ => f.severity.normal(),
        };
        println!(
            "[{}] {}:{} — {} ({})",
            sev, f.file, f.line, f.rule, f.masked_value
        );
    }
}

fn to_markdown(findings: &[scanner::Finding]) -> String {
    let mut out = String::from("# Relatório secretscan-rs\n\n");
    out.push_str(&format!("Total: {} achados\n\n", findings.len()));
    out.push_str("| Severidade | Arquivo | Linha | Regra | Valor mascarado |\n");
    out.push_str("|---|---|---|---|---|\n");
    for f in findings {
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            f.severity, f.file, f.line, f.rule, f.masked_value
        ));
    }
    out
}

fn write_output(content: &str, out_file: &Option<PathBuf>) -> anyhow::Result<()> {
    match out_file {
        Some(path) => {
            std::fs::write(path, content)?;
            println!("Relatório salvo em {:?}", path);
        }
        None => println!("{}", content),
    }
    Ok(())
}
