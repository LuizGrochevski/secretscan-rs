use crate::patterns::{mask, PATTERNS};
use anyhow::Result;
use ignore::WalkBuilder;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize, Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: String,
    pub masked_value: String,
}

const SUPPRESS_MARKER: &str = "secretscan-ignore";

pub fn scan_path(root: &Path, exclude: &[String]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);

    for entry in walker.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }

        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();

        if exclude.iter().any(|ex| path_str.contains(ex.as_str())) {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (idx, line) in content.lines().enumerate() {
            if line.contains(SUPPRESS_MARKER) {
                continue;
            }

            for pattern in PATTERNS.iter() {
                // Se o regex tem grupos de captura, usa o último grupo
                // como o valor real do segredo (evita mascarar a linha
                // inteira, ex: "password = " junto com o valor).
                if let Some(caps) = pattern.regex.captures(line) {
                    let matched_value = caps
                        .iter()
                        .skip(1)
                        .filter_map(|g| g)
                        .last()
                        .map(|g| g.as_str())
                        .unwrap_or_else(|| caps.get(0).unwrap().as_str());

                    findings.push(Finding {
                        file: path_str.clone(),
                        line: idx + 1,
                        rule: pattern.name.to_string(),
                        severity: pattern.severity.to_string(),
                        masked_value: mask(matched_value),
                    });
                }
            }
        }
    }

    Ok(findings)
}
