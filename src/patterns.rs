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

#[cfg(test)]
mod tests {
    use super::*;

    fn matches_rule(rule_name: &str, line: &str) -> bool {
        PATTERNS
            .iter()
            .find(|p| p.name == rule_name)
            .map(|p| p.regex.is_match(line))
            .unwrap_or(false)
    }

    #[test]
    fn detects_aws_access_key() {
        assert!(matches_rule(
            "aws_access_key_id",
            r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE""#
        ));
    }

    #[test]
    fn does_not_flag_short_random_string_as_aws_key() {
        assert!(!matches_rule("aws_access_key_id", "AKIA123"));
    }

    #[test]
    fn detects_github_pat_classic() {
        assert!(matches_rule(
            "github_pat_classic",
            "token = ghp_1234567890abcdef1234567890abcdef1234"
        ));
    }

    #[test]
    fn detects_stripe_live_key() {
        let fake_key = format!("sk_live_{}", "A".repeat(24));
        let line = format!("STRIPE_KEY={}", fake_key);
        assert!(matches_rule("stripe_live_key", &line));
    }

    #[test]
    fn detects_slack_token() {
        let fake_token = format!("{}-{}-{}", "xoxb", "0000000000", "a".repeat(16));
        let line = format!("SLACK_WEBHOOK={}", fake_token);
        assert!(matches_rule("slack_token", &line));
    }

    #[test]
    fn detects_google_api_key() {
        assert!(matches_rule(
            "google_api_key",
            "key: AIzaSyD-1234567890abcdefghijklmnopqrstu"
        ));
    }

    #[test]
    fn detects_private_key_block() {
        assert!(matches_rule(
            "private_key_block",
            "-----BEGIN RSA PRIVATE KEY-----"
        ));
    }

    #[test]
    fn detects_jwt_token() {
        assert!(matches_rule(
            "jwt_token",
            "auth = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def456"
        ));
    }

    #[test]
    fn detects_generic_password_assignment() {
        assert!(matches_rule(
            "generic_secret_assignment",
            r#"password = "SuperSecreta123""#
        ));
    }

    #[test]
    fn does_not_flag_short_generic_value() {
        // valor com menos de 6 caracteres não deve disparar
        assert!(!matches_rule("generic_secret_assignment", r#"password = "abc""#));
    }

    #[test]
    fn does_not_flag_unrelated_line() {
        for pattern in PATTERNS.iter() {
            assert!(!pattern.regex.is_match("fn main() { println!(\"hello world\"); }"));
        }
    }

    #[test]
    fn mask_short_value_fully_hidden() {
        assert_eq!(mask("abc123"), "******");
    }

    #[test]
    fn mask_long_value_shows_edges() {
        let masked = mask("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKI"));
        assert!(masked.ends_with("PLE"));
        assert!(masked.contains('*'));
    }
}
