use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

// Extrai valores entre aspas (simples ou duplas) com pelo menos 20
// caracteres — abaixo disso a entropia não é um sinal confiável.
static QUOTED_STRING: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""([^"]{20,})"|'([^']{20,})'"#).unwrap());

const MIN_LENGTH: usize = 20;
// Thresholds inspirados no trufflehog: base64 tem alfabeto maior (64
// símbolos), então o teto teórico de entropia é maior (6 bits/char) e o
// limiar precisa ser mais alto pra não pegar toda string comprida.
// Hex tem alfabeto de 16 símbolos (4 bits/char de teto), então usamos
// um limiar mais baixo, mas isso também significa que hashes git,
// UUIDs, etc. vão disparar com frequência — é uma limitação conhecida
// dessa técnica, por isso ela é só um fallback opt-in.
const BASE64_THRESHOLD: f64 = 4.5;
const HEX_THRESHOLD: f64 = 3.0;

// Valores comuns de teste/exemplo que não devem ser reportados mesmo
// se baterem no threshold de entropia.
const ALLOWLIST_SUBSTRINGS: &[&str] = &[
    "example", "changeme", "xxxxxxxx", "00000000", "11111111",
    "placeholder", "your_key_here", "insert_key",
];

fn shannon_entropy(s: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base64_charset(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn is_allowlisted(s: &str) -> bool {
    let lower = s.to_lowercase();
    ALLOWLIST_SUBSTRINGS.iter().any(|a| lower.contains(a))
}

/// Retorna os valores candidatos (com aparência de segredo por alta
/// entropia) encontrados numa linha. Cada item é (valor, entropia).
pub fn detect_high_entropy(line: &str) -> Vec<(String, f64)> {
    let mut results = Vec::new();

    for caps in QUOTED_STRING.captures_iter(line) {
        let value = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");

        if value.len() < MIN_LENGTH || is_allowlisted(value) {
            continue;
        }

        let entropy = shannon_entropy(value);

        let flagged = if is_hex(value) {
            entropy >= HEX_THRESHOLD
        } else if is_base64_charset(value) {
            entropy >= BASE64_THRESHOLD
        } else {
            false // charset fora do esperado (ex: frase com espaços) — ignora
        };

        if flagged {
            results.push((value.to_string(), entropy));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_random_looking_base64_string() {
        let line = r#"token = "aB3xK9mQz7Lp2VnY8sT4wR6uH1cF5eJ0d""#;
        let results = detect_high_entropy(line);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn does_not_flag_short_string() {
        let line = r#"name = "short_value""#;
        let results = detect_high_entropy(line);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_repetitive_string() {
        let line = r#"filler = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;
        let results = detect_high_entropy(line);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_allowlisted_example_value() {
        let line = r#"key = "this_is_an_example_value_not_real""#;
        let results = detect_high_entropy(line);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_plain_english_sentence() {
        let line = r#"description = "this is just a normal english sentence here""#;
        let results = detect_high_entropy(line);
        assert!(results.is_empty());
    }
}
