# Hardening Baseline (secure-by-default)

Apply what is missing; adapt to the stack. Every item must be tested against the real app so it does not break functionality. Prefer framework-native mechanisms (helmet, Django `SECURE_*` settings, Spring Security, `secure_headers` gem, ASP.NET middleware) over hand-rolled headers.

## HTTP security headers
| Header | Recommended value | Notes |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'nonce-{rand}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` | Build from what the app actually loads (CDNs, analytics, fonts). Roll out with `-Report-Only` if uncertain, check the console, then enforce. Avoid `unsafe-inline`/`unsafe-eval`. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (add `preload` only with user consent) | Only over HTTPS. |
| `X-Content-Type-Options` | `nosniff` | |
| `X-Frame-Options` | `DENY` (or `SAMEORIGIN` if self-framing is used) | Redundant with `frame-ancestors`, keep for old browsers. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or `no-referrer`) | |
| `Permissions-Policy` | disable unused: `camera=(), microphone=(), geolocation=()` | Keep those the app uses. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Check OAuth popups still work (`same-origin-allow-popups` if not). |
| `Cross-Origin-Resource-Policy` | `same-origin` for private assets | |
| `Cache-Control` | `no-store` on authenticated/sensitive responses | |
| Remove | `X-Powered-By`, `Server` version banners | |

## Cookies & sessions
`HttpOnly; Secure; SameSite=Lax` (Strict where UX allows); `__Host-` prefix; rotation on login; server-side invalidation on logout; idle + absolute timeouts; session store not in-memory in prod.

## CORS
Config-driven exact allowlist; credentials only for listed origins; restrict methods/headers; `Vary: Origin`; no wildcard on authenticated APIs.

## CSRF
Framework CSRF protection enabled for cookie-auth forms/APIs; SameSite cookies; Origin check.

## Rate limiting & abuse
Login, signup, password reset, OTP, search/export, expensive endpoints. Per-IP and per-account keys; shared store (Redis) in multi-instance deployments; correct client-IP extraction behind proxies (`trust proxy` set to the actual hop count, not `true`).

## Errors & logging
Production error handler returns generic messages + correlation id; debug off (`DEBUG=False`, `NODE_ENV=production`, `app.debug=False`, Spring `server.error.include-stacktrace=never`). Log security events (login success/failure, authz denials, password/MFA changes, admin actions) with user id, IP, timestamp — never passwords, tokens, full card numbers or secrets. Redaction in the logger config.

## Secrets & configuration
No secrets in repo, images, frontend bundles or logs; `.env.example` with placeholders; startup validation of required config (fail closed); separate per-environment secrets; least-privilege service credentials (DB user, cloud IAM, API keys scoped). Disable directory listing, default credentials, sample apps, admin consoles exposed publicly, source maps in prod (or private).

## Transport
HTTPS-only, redirect HTTP→HTTPS, TLS 1.2+; secure WebSockets (`wss://`) with origin check and auth on connect.

## Dependencies & supply chain
Auditor clean or residuals documented with justification; lockfile committed; `npm ci`; no `postinstall` from untrusted packages; Dependabot/Renovate; SCA + SAST (Semgrep/CodeQL) + secret scanning in CI; pin CI actions by SHA; least-privilege `GITHUB_TOKEN` permissions.

## Containers & IaC
Non-root user, minimal/distroless base, pinned digests, no secrets in layers/build args, read-only root FS where possible, drop capabilities, healthcheck; `.dockerignore` excludes `.env`, `.git`. Cloud: private buckets by default, IMDSv2, security groups least-open, DB not publicly reachable, encryption at rest.

## Database
Least-privilege app user (no DDL/superuser in runtime), TLS to DB, backups encrypted, migrations run with a separate privileged identity.

## Frontend
No secrets in client code; tokens preferably in HttpOnly cookies rather than `localStorage`; `rel="noopener noreferrer"` on `target=_blank` to untrusted URLs; Subresource Integrity on third-party CDN scripts; `postMessage` with explicit target origin and origin checks on receive; strip sensitive data from client-side state/logs.
