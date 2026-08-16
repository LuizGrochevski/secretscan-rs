use crate::patterns::{mask, PATTERNS};
use crate::scanner::Finding;
use anyhow::{bail, Result};
use std::path::Path;
use std::process::Command;

const SUPPRESS_MARKER: &str = "secretscan-ignore";

/// Escaneia o histórico completo do git (todos os commits, todas as
/// branches) em busca de segredos que foram commitados em algum momento,
/// mesmo que já tenham sido removidos do estado atual do working directory.
pub fn scan_git_history(repo_path: &Path) -> Result<Vec<Finding>> {
    // Confere se é mesmo um repo git antes de tentar rodar git log
    let check = Command::new("git")
        .args(["-C", repo_path.to_str().unwrap_or("."), "rev-parse", "--is-inside-work-tree"])
        .output()?;

    if !check.status.success() {
        bail!("O caminho informado não é um repositório git");
    }

    // -p: mostra o diff de cada commit
    // --all: percorre todas as branches, não só a atual
    // -U0: zero linhas de contexto, só as linhas realmente adicionadas/removidas
    let output = Command::new("git")
        .args([
            "-C",
            repo_path.to_str().unwrap_or("."),
            "log",
            "-p",
            "--all",
            "-U0",
            "--no-color",
        ])
        .output()?;

    if !output.status.success() {
        bail!("Falha ao executar git log");
    }

    let log_text = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    let mut current_commit = String::new();
    let mut current_file = String::new();

    for line in log_text.lines() {
        if let Some(hash) = line.strip_prefix("commit ") {
            current_commit = hash.chars().take(8).collect();
            continue;
        }

        if let Some(rest) = line.strip_prefix("+++ b/") {
            current_file = rest.to_string();
            continue;
        }

        // Só nos interessam linhas ADICIONADAS (começam com + mas não são
        // o cabeçalho "+++"), já que queremos achar segredos que entraram
        // no histórico em algum commit, não os que foram removidos.
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }

        let content = &line[1..]; // remove o '+' inicial

        if content.contains(SUPPRESS_MARKER) {
            continue;
        }

        for pattern in PATTERNS.iter() {
            if let Some(caps) = pattern.regex.captures(content) {
                let matched_value = caps
                    .iter()
                    .skip(1)
                    .filter_map(|g| g)
                    .last()
                    .map(|g| g.as_str())
                    .unwrap_or_else(|| caps.get(0).unwrap().as_str());

                findings.push(Finding {
                    file: format!("{} (commit {})", current_file, current_commit),
                    line: 0, // git log -p não numera linha do arquivo, só do diff
                    rule: format!("git_history:{}", pattern.name),
                    severity: pattern.severity.to_string(),
                    masked_value: mask(matched_value),
                });
            }
        }
    }

    Ok(findings)
}
