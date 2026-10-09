# Hardening Report Template & Scoring

Write `security-audit/HARDENING-REPORT.md` in the user's language. Evidence-driven; never claim "100% secure". Redact secrets.

---

# Relatório de Hardening — <app name>

**Data:** <YYYY-MM-DD> · **Engenheiro:** Web Defensive Security (Claude Code) · **Escopo:** <repos/paths/env> · **Entrada:** <`security-audit/findings.json` de <data> | auditoria própria> · **Branch/commit inicial:** <...> · **Método:** estático + testes automatizados <+ re-ataque dinâmico local, se autorizado>

## 1. Resumo executivo
Postura antes vs depois, o que foi corrigido, o que permanece, mudanças incompatíveis, segredos que precisam ser rotacionados, e a frase de nível de segurança suportado pelas verificações (ex.: "Todos os 9 findings confirmados foram corrigidos e re-testados; nenhuma vulnerabilidade Crítica/Alta conhecida permanece no escopo testado. Não foram testados: X, Y.").

| | Antes | Depois |
|---|---|---|
| Security Score | NN (banda) | NN (banda) |
| Critical / High / Medium / Low | a/b/c/d | a/b/c/d |

## 2. Revalidação dos findings de entrada
Tabela: `ID | Título | Severidade original | Status da revalidação (confirmed/false-positive/already-fixed/needs-info) | Severidade reavaliada | Justificativa`.

## 3. Vulnerabilidades corrigidas
Uma subseção por finding, por prioridade:

### <ID> — <Título> · <Severidade> · Status: fixed | partially-fixed
- **Causa raiz:** o controle ausente e por que existia (source → sink).
- **Correção aplicada:** o que foi mudado e por que corrige a causa (não o sintoma); camadas de defense-in-depth adicionadas.
- **Arquivos/linhas modificados:** `path:linhas` (uma linha por arquivo, inclusive variantes encontradas em outros pontos).
- **Compatibilidade/UX:** o que mudou para usuários/clientes (ideal: nada); mudanças incompatíveis destacadas.
- **Testes:** testes adicionados (`arquivo::nome`), resultado antes da correção (falhava = reproduzia) e depois (passa); teste positivo de funcionalidade.
- **Re-ataque:** PoC original + variantes de bypass tentadas → resultado.

## 4. Arquivos/linhas modificados (consolidado)
`Arquivo | Linhas | Finding(s) | Tipo de mudança`.

## 5. Testes realizados
- Baseline antes das mudanças: comandos executados e resultado (X pass / Y fail pré-existentes).
- Depois: mesmos comandos + novos testes de segurança. Regressões: nenhuma / listar.
- Lint / type-check / build / auditoria de dependências: resultados.
- Validação dinâmica local (se autorizada): o que foi exercitado.

## 6. Dependências e configurações endurecidas
Dependências atualizadas (`pacote: de → para, CVE/GHSA`), headers, cookies, CORS, CSRF, rate limit, tratamento de erros, logging, secrets, CI, containers/IaC — cada item com arquivo e como foi verificado.

## 7. Vulnerabilidades residuais
`ID | Severidade | Status (open/partially-fixed/accepted-risk/false-positive/not-tested) | Motivo | Mitigação existente | Próximo passo`. Inclua o que exige ação fora do código (rotação de segredos, configuração de cloud, WAF, decisão de produto).

## 8. Security Score antes/depois
Mostre a aritmética de ambos com a fórmula abaixo.

## 9. Relatório final de hardening
Postura por categoria (Injection, XSS, Authn, Authz/IDOR, Session, CSRF, CORS, SSRF, Path/Upload, Deserialization/RCE, JWT/OAuth, Secrets, Headers, Deps, Config/Infra, Business logic): `Antes | Depois | Verificado por (teste/re-ataque/estático) | Notas`. Declare explicitamente o nível de confiança e as lacunas de cobertura.

## 10. Recomendações futuras
Priorizadas: SAST/SCA/secret scanning no CI, testes de segurança obrigatórios em PR, threat modeling de novas features, pentest periódico, monitoramento/alertas de eventos de segurança, rotação de segredos, MFA, revisão de IAM, bug bounty, etc. Somente o que é relevante a este projeto.

---

## Security Score formula (0–100) — identical to web-offensive-security

Start at **100**, subtract per **open** finding by severity, floor at 0:

| Severity | Penalty each |
|----------|--------------|
| Critical | 25 |
| High | 12 |
| Medium | 5 |
| Low | 2 |
| Info | 0 |

- Any open **Critical** caps the score at ≤ 40; any open **High** caps at ≤ 70.
- Verified findings count at full penalty; unverified static-only findings at 60% (round up).
- `partially-fixed` findings count at full penalty of their *residual* severity (re-assess it).
- `false-positive` and `fixed` (test + re-attack passed) findings count 0.
- Band: 90–100 Strong · 75–89 Good · 50–74 Needs work · 25–49 Weak · 0–24 Critical.

**Before** = the offensive report's score if one exists (recompute it if re-validation changed severities or marked false positives — show both). **After** = remaining open/partial findings + any new findings discovered during remediation. Always show the arithmetic. A score of 100 means "no known open findings in the tested scope", never "invulnerable".
