use crate::entropy::detect_high_entropy;
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

pub fn scan_path(root: &Path, exclude: &[String], entropy: bool) -> Result<Vec<Finding>> {
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

            let mut matched_known_pattern = false;

            for pattern in PATTERNS.iter() {
                // Se o regex tem grupos de captura, usa o último grupo
                // como o valor real do segredo (evita mascarar a linha
                // inteira, ex: "password = " junto com o valor).
                if let Some(caps) = pattern.regex.captures(line) {
                    matched_known_pattern = true;
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

            // Fallback por entropia: só roda se nenhum padrão conhecido
            // já bateu nessa linha (evita relatório duplicado) e só se
            // o usuário ativou explicitamente com --entropy.
            if entropy && !matched_known_pattern {
                for (value, score) in detect_high_entropy(line) {
                    findings.push(Finding {
                        file: path_str.clone(),
                        line: idx + 1,
                        rule: format!("high_entropy_string ({:.2} bits/char)", score),
                        severity: "LOW".to_string(),
                        masked_value: mask(&value),
                    });
                }
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("secretscan_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_secret_in_file() {
        let dir = make_temp_dir("finds_secret");
        fs::write(
            dir.join("config.py"),
            r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE""#, // secretscan-ignore
        )
        .unwrap();

        let findings = scan_path(&dir, &[], false).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "aws_access_key_id");
        assert_eq!(findings[0].severity, "HIGH");
    }

    #[test]
    fn respects_suppression_marker() {
        let dir = make_temp_dir("suppression");
        fs::write(
            dir.join("config.py"),
            r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  # secretscan-ignore"#,
        )
        .unwrap();

        let findings = scan_path(&dir, &[], false).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn respects_exclude_argument() {
        let dir = make_temp_dir("exclude");
        fs::create_dir_all(dir.join("vendor")).unwrap();
        fs::write(
            dir.join("vendor/lib.py"),
            r#"password = "SuperSecreta123""#, // secretscan-ignore
        )
        .unwrap();

        let findings = scan_path(&dir, &["vendor".to_string()], false).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn returns_empty_for_clean_directory() {
        let dir = make_temp_dir("clean");
        fs::write(dir.join("main.py"), "print('hello world')").unwrap();

        let findings = scan_path(&dir, &[], false).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
