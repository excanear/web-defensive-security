# Web-Defensive-Security — Claude Code Skill

Skill do [Claude Code](https://claude.com/claude-code) que atua como um especialista sênior em AppSec/Blue Team para **corrigir sistematicamente vulnerabilidades em aplicações web** — na causa raiz, preservando funcionalidade, UX e compatibilidade.

Funciona em par com a skill `web-offensive-security`: lê o relatório dela (`security-audit/findings.json` + `REPORT.md`), revalida cada finding e corrige apenas o que for confirmado.

## O que ela faz

1. **Baseline** — roda testes/lint/build antes de qualquer mudança.
2. **Ingestão e revalidação** dos findings ofensivos (`confirmed` / `false-positive` / `already-fixed` / `needs-info`).
3. **Auditoria defensiva própria** (findings novos `WDS-NNN`).
4. **Correção por finding**: teste de segurança que falha primeiro → correção da causa raiz (na camada compartilhada) → caça de variantes → teste positivo de funcionalidade → suíte completa → re-ataque com bypasses.
5. **Hardening secure-by-default**: headers/CSP, cookies, CORS, CSRF, rate limit, erros/logging, secrets, dependências, CI, containers/IaC.
6. **Re-análise ofensiva final** de todos os findings e attack chains.
7. **Relatório** `security-audit/HARDENING-REPORT.md` + `security-audit/remediation.json`.

Cobre: frontend, backend, APIs, autenticação/autorização, sessões, cookies, headers, CORS, CSRF, XSS, injection, SSRF, IDOR/BOLA, RCE, command injection, path traversal, uploads, JWT/OAuth, secrets, exposição de dados, validação, dependências, configurações e lógica de negócio.

## Garantias

- Nunca remove uma funcionalidade para esconder uma vulnerabilidade.
- Nunca introduz secrets, backdoors ou acessos privilegiados.
- Proíbe patches superficiais (blocklists, regex de strip, checagens só no client).
- Nunca declara o sistema "100% invulnerável" — apenas o nível suportado pelas verificações realizadas.
- Security Score antes/depois com a mesma fórmula da skill ofensiva (comparável).

## Instalação

```bash
git clone https://github.com/excanear/web-defensive-security.git
# Linux/macOS
cp -r web-defensive-security/web-defensive-security ~/.claude/skills/
# Windows (PowerShell)
Copy-Item -Recurse web-defensive-security\web-defensive-security "$env:USERPROFILE\.claude\skills\"
```

Depois, no Claude Code: `/web-defensive-security` (ou peça para "corrigir/endurecer a segurança" da aplicação).

## Estrutura

```
web-defensive-security/
├── SKILL.md                         # regras e workflow
└── references/
    ├── remediation-playbook.md      # causa raiz → correção segura por classe/stack
    ├── hardening-baseline.md        # baseline secure-by-default
    ├── security-testing.md          # testes de regressão + checklist de bypass
    ├── report-template.md           # HARDENING-REPORT + fórmula do Security Score
    └── remediation-schema.json      # schema do remediation.json
```

## Uso responsável

Use apenas em projetos e ambientes que você tem autorização para modificar e testar.
