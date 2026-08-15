use once_cell::sync::Lazy;
use regex::Regex;

pub struct SecretPattern {
    pub name: &'static str,
    pub regex: Regex,
    pub severity: &'static str,
}

pub static PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        SecretPattern {
            name: "aws_access_key_id",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "aws_secret_access_key",
            regex: Regex::new(r#"(?i)aws_secret_access_key\s*=\s*["']?[A-Za-z0-9/+=]{40}["']?"#).unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "github_pat_classic",
            regex: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "github_pat_fine_grained",
            regex: Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "stripe_live_key",
            regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "slack_token",
            regex: Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "google_api_key",
            regex: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "private_key_block",
            regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----").unwrap(),
            severity: "HIGH",
        },
        SecretPattern {
            name: "jwt_token",
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}").unwrap(),
            severity: "MEDIUM",
        },
        SecretPattern {
            name: "generic_secret_assignment",
            regex: Regex::new(r#"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["']([^"'\s]{6,})["']"#).unwrap(),
            severity: "MEDIUM",
        },
    ]
});

/// Substitui o valor do segredo por uma versão mascarada (primeiros e
/// últimos 3 caracteres visíveis) para não vazar o valor real no relatório.
pub fn mask(value: &str) -> String {
    if value.len() <= 8 {
        return "*".repeat(value.len());
    }
    let start = &value[..3];
    let end = &value[value.len() - 3..];
    format!("{}{}{}", start, "*".repeat(value.len() - 6), end)
}
