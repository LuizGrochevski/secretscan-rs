# secretscan-rs 🔐🦀

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20(Termux)-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)

secretscan-rs é uma ferramenta em **Rust** para detectar segredos expostos em código-fonte (chaves de API, senhas, tokens, chaves privadas), com foco em uso local e integração em CI/CD via pre-commit hook.

Faz parte da mesma família de projetos de segurança que o **[apisec-rs](https://github.com/LuizGrochevski/apisec-rs)** e o **[javasast-rs](https://github.com/LuizGrochevski/javasast-rs)**.

---

## 🚀 Funcionalidades

- 🔍 Varredura recursiva de diretórios, `.gitignore`-aware (via crate `ignore`)
- 🔑 Detecção de padrões conhecidos: AWS Access Key, GitHub PAT (clássico e fine-grained), Stripe live key, Slack token, Google API key, blocos de chave privada (RSA/EC/OpenSSH/DSA), JWT, atribuições genéricas de senha/secret/token
- 🎭 Mascaramento do valor detectado no relatório (não expõe o segredo real)
- 🚫 Suppression inline via comentário `secretscan-ignore` na linha
- 📁 Exclusão de caminhos via `--exclude` (substring match)
- 📊 Exportação de relatório em texto colorido, JSON e Markdown
- 🚦 Flag `--fail-on high|medium` para uso em CI/CD (exit code 1 se encontrar achados na severidade configurada ou acima)

---

## 🧠 Arquitetura

```
Diretório/arquivo alvo
   ↓
Walker (.gitignore-aware, via crate `ignore`)
   ↓
Leitura linha a linha
   ↓
Matching contra padrões conhecidos (regex)
   ├── Suppression check (secretscan-ignore)
   └── Extração + mascaramento do valor capturado
   ↓
Relatório (terminal colorido, JSON, Markdown)
```

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| Rust | Linguagem principal |
| Regex | Matching dos padrões de segredo |
| once_cell | Compilação lazy dos padrões |
| ignore | Varredura de diretório .gitignore-aware |
| Clap | CLI arguments |
| Serde / serde_json | Serialização JSON |
| Colored | Output colorido no terminal |
| Anyhow | Tratamento de erros |

---

## 📦 Instalação

### Linux
```bash
git clone https://github.com/LuizGrochevski/secretscan-rs.git
cd secretscan-rs
cargo build --release
```

### Termux (Android/ARM)
```bash
pkg update && pkg upgrade
pkg install rust clang make git
git clone https://github.com/LuizGrochevski/secretscan-rs.git
cd secretscan-rs
cargo build --release
```

---

## 📄 Exemplos de uso

**Scan básico**
```bash
./secretscan-rs ./meu-projeto
```

**Excluindo diretórios**
```bash
./secretscan-rs . --exclude tests,vendor
```

**Exportando relatório em Markdown**
```bash
./secretscan-rs . --output markdown --out-file report.md
```

**Exportando relatório em JSON**
```bash
./secretscan-rs . --output json --out-file report.json
```

**Uso em CI/CD (falha o build em achado HIGH)**
```bash
./secretscan-rs . --fail-on high
```

---

## 🚫 Suprimindo um falso positivo

```python
token = "valor-de-teste-nao-real"  # secretscan-ignore
```

---

## 🛣️ Roadmap

- [x] Padrões de detecção (AWS, GitHub, Stripe, Slack, Google, chave privada, JWT, atribuição genérica)
- [x] Varredura de diretório `.gitignore`-aware
- [x] Mascaramento do valor real no relatório
- [x] Suppression inline (`secretscan-ignore`)
- [x] Exclusão de caminhos (`--exclude`)
- [x] Exportação JSON e Markdown
- [x] `--fail-on` para CI/CD
- [x] Scan de histórico do git (commits antigos, não só working directory)
- [ ] Detecção por entropia (fallback para secrets sem padrão fixo conhecido)
- [ ] Testes automatizados (unit tests por regra)
- [ ] Pre-commit hook de exemplo

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

---

## ⚠️ Aviso

Este projeto é destinado exclusivamente para fins educacionais e auditorias autorizadas em ambientes controlados. Segredos detectados são mascarados no relatório, mas revise antes de compartilhar qualquer output publicamente.

