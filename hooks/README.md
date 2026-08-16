# Pre-commit hook

O Git não versiona nem ativa hooks automaticamente (eles vivem em
`.git/hooks`, que não é rastreado pelo controle de versão). Por isso,
o hook fica aqui em `hooks/` e precisa ser instalado manualmente em
cada repositório onde você quiser usá-lo.

## Instalação manual

No repositório onde você quer o hook ativo:

```bash
cp /caminho/para/secretscan-rs/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Configurando o caminho do binário

Por padrão, o hook procura `secretscan-rs` no `PATH`. Se o seu binário
não estiver no `PATH`, exporte a variável `SECRETSCAN_BIN` antes de
commitar, ou adicione ao seu `.bashrc`:

```bash
export SECRETSCAN_BIN="$HOME/secretscan-rs/target/release/secretscan-rs"
```

## Instalação em múltiplos repositórios (opcional)

Se você quiser que o hook rode automaticamente em todo repositório
novo, configure um `core.hooksPath` global apontando pra uma pasta
com este hook, ou copie manualmente após cada `git clone`/`git init`.

## Testando

```bash
echo 'aws_access_key_id = "AKIA_EXEMPLO_NAO_REAL"' > teste_secret.py
git add teste_secret.py
git commit -m "teste"
```

O commit deve ser bloqueado com uma mensagem de erro apontando o
achado HIGH. Remova o arquivo de teste depois:

```bash
git reset HEAD teste_secret.py
rm teste_secret.py
```
