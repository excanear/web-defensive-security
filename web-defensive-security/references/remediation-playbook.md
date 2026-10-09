# Remediation Playbook

For each class: **root cause → secure fix → variant hunting**. Always fix the shared layer when one exists, then grep for sibling call sites. Pair each fix with a negative (exploit blocked) and positive (legit use works) test.

---

## Injection

### SQL injection (CWE-89)
- **Root cause:** untrusted data concatenated/interpolated into a query string.
- **Fix:** bound parameters everywhere.
  - Node: `db.query('SELECT * FROM u WHERE id = $1', [id])`; Knex/Prisma/Sequelize bindings; never `sequelize.query(\`...${x}\`)`, `$queryRawUnsafe`, `knex.raw` with interpolation.
  - Python: `cursor.execute("... WHERE id = %s", (id,))`; SQLAlchemy `text(":id")` with params; Django ORM, never `.extra()`/`.raw()` with f-strings.
  - Java: `PreparedStatement`, JPA named params; never string-built JPQL/HQL.
  - PHP: PDO prepared statements with `ATTR_EMULATE_PREPARES=false`.
  - Go: `db.Query("... $1", v)`.
- Identifiers (ORDER BY column, direction, table) cannot be bound → **allowlist map** (`{"name":"u.name","date":"u.created_at"}`), reject anything else.
- Defense-in-depth: DB user with least privilege (no DDL, no superuser), schema validation of types at the boundary.
- **Variants:** grep raw/unsafe query APIs, template literals near `query(`, `LIKE` building, `IN (...)` lists, stored procedures building dynamic SQL, reporting/export endpoints, migrations scripts reachable at runtime.

### NoSQL injection (CWE-943)
- **Root cause:** request objects passed straight into query filters (`{ user: req.body.user }` where body is `{"$ne":null}`), or `$where`/`mapReduce` with user JS.
- **Fix:** schema-validate types (zod/joi/pydantic/class-validator) so a string field cannot be an object; cast (`String(x)`); `mongoose.set('sanitizeFilter', true)`; never `$where` with input.

### Command injection / RCE (CWE-78, CWE-94)
- **Root cause:** shell invocation with input (`exec`, `system`, `os.popen`, `shell=True`, backticks) or dynamic code evaluation (`eval`, `new Function`, `vm`, `pickle.loads`, `yaml.load`, `unserialize`, `ObjectInputStream`, SSTI via `render_template_string(user)`).
- **Fix:** prefer a native library (e.g. `sharp` instead of shelling to ImageMagick). If a process is required: `execFile`/`spawn` with arg array and `shell:false`; `subprocess.run([...], shell=False)`; allowlist values; put `--` before positional args to stop option injection. Replace `eval` with a parser/lookup table. Use safe deserializers (`yaml.safe_load`, JSON, type-allowlisted deserialization). Templates: never compile user input as a template; pass it as data.
- **Variants:** child_process across repo, cron/job runners, PDF/image conversion, git/ffmpeg wrappers, admin "diagnostics" (ping/traceroute) features.

### LDAP / XPath / header / log injection
- Use library escaping for LDAP filters/DN; parameterized XPath; reject CR/LF in values that reach headers (most frameworks do — verify custom `res.setHeader` uses); encode/strip control chars in log messages (CWE-117).

---

## XSS (CWE-79)
- **Root cause:** untrusted data rendered into HTML/JS/URL/CSS context without context-appropriate encoding, or passed to DOM sinks.
- **Fix:**
  - Rely on auto-escaping templates (React JSX, Vue `{{ }}`, Jinja2 autoescape, Thymeleaf `th:text`, Blade `{{ }}`). Remove `dangerouslySetInnerHTML`, `v-html`, `|safe`, `{!! !!}`, `th:utext`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` with untrusted data → use `textContent` / framework binding.
  - When rich HTML is a genuine requirement (preserve the feature!): sanitize with DOMPurify (client) or a maintained server sanitizer (bleach-successor `nh3`, OWASP Java HTML Sanitizer, `sanitize-html`) with a strict allowlist, on output or both.
  - URLs in `href`/`src`: allow only `http:`, `https:`, `mailto:` (parse with `URL`, check `protocol`); blocks `javascript:`/`data:`.
  - Data into inline scripts: serialize with a safe JSON encoder that escapes `<`, `>`, `&`, U+2028/2029 (e.g. `serialize-javascript`, Django `json_script`).
  - Defense-in-depth: strict CSP (nonce/hash-based, no `unsafe-inline`), `HttpOnly` session cookies, Trusted Types where feasible.
- **Variants:** error pages reflecting params, markdown renderers, PDF/email templates, SVG uploads served inline, `postMessage` handlers without origin checks, `location.hash`/`URLSearchParams` → DOM sinks, jQuery `$(userInput)`, `.html()`.

---

## Authentication (CWE-287, 307, 521, 640)
- Passwords: argon2id or bcrypt (cost ≥ 12) / scrypt; never MD5/SHA*/unsalted. Migrate legacy hashes on next login (rehash) — do not force-reset all users unless required.
- Brute force: rate limit + progressive delay per account and per IP; generic error messages ("invalid credentials") and constant-ish timing to prevent user enumeration (also on signup/reset).
- Password reset: CSPRNG tokens (≥128 bits), stored hashed, single-use, short expiry, bound to user; build reset links from a configured base URL, **never from the `Host` header**.
- MFA: verify server-side, rate-limit OTP attempts, do not let the MFA step be skipped by calling the post-MFA endpoint directly.
- Constant-time comparison for tokens/HMACs (`crypto.timingSafeEqual`, `hmac.compare_digest`).

## Authorization — IDOR/BOLA/BFLA, privilege escalation (CWE-639, 285, 862, 863)
- **Root cause:** object fetched by client-supplied id without verifying the caller's right to it; role checks missing on functions; deny-by-default absent.
- **Fix:** central policy layer (middleware/guard/decorator/policy class). Scope queries by owner/tenant: `findFirst({ where: { id, ownerId: user.id } })` → 404 when not found (avoid existence oracle). Function-level: role/permission guard applied by default on routers, explicit `@Public` allowlist. Multi-tenant: tenant id comes from the session, never from the request body.
- **Mass assignment (CWE-915):** explicit DTOs / `pick` allowlists; never `Model.update(req.body)`; block `role`, `isAdmin`, `ownerId`, `tenantId`, `balance`, `verified`.
- **Variants:** every route with `:id`, nested resources (`/orgs/:o/projects/:p` — check both levels), bulk/export endpoints, GraphQL resolvers and field-level auth, websocket events, file download by name, admin APIs reachable without admin role, older API versions.

## Sessions & cookies (CWE-384, 613, 614, 1004)
- Regenerate session id on login and privilege change; invalidate on logout server-side; idle + absolute timeouts; invalidate other sessions on password change.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), narrow `Path`, no `Domain` unless needed, `__Host-` prefix for session cookies when possible.
- Session secret strong, from env, rotatable.

## JWT / OAuth / OIDC (CWE-347, 345)
- JWT: verify with explicit `algorithms: ['RS256']` (or the one used); reject `none`; never use the token's `alg`/`kid`/`jku`/`x5u` to pick keys from untrusted sources; validate `exp`, `nbf`, `iss`, `aud`; short access-token TTL; refresh token rotation with reuse detection; strong HS secret (≥256 bits) from secret manager. Don't put sensitive data in payload. Revocation strategy for logout/compromise.
- OAuth/OIDC: exact-match `redirect_uri` allowlist; `state` (CSRF) and PKCE (S256) on all clients; validate `nonce` and ID token signature/issuer/audience; Authorization Code flow, not implicit; don't log codes/tokens; account linking only on verified emails.

## CSRF (CWE-352)
- Cookie-authenticated state-changing requests need: `SameSite=Lax/Strict` **plus** a synchronizer or double-submit (signed) token, or strict `Origin` header verification. Never state changes on GET. Bearer-token APIs (header-sent, not cookies) are not CSRF-prone — don't add tokens there needlessly; ensure the API doesn't *also* accept cookie auth.
- Login CSRF and logout CSRF count too.

## CORS (CWE-942)
- Exact-match allowlist of origins from config; never reflect `Origin` blindly; never `*` with credentials; don't trust `null` origin; anchor regexes (`^https://app\.example\.com$`); add `Vary: Origin`.

## SSRF (CWE-918)
- **Root cause:** server fetches a URL/host derived from input.
- **Fix:** prefer allowlist of hosts or of pre-registered destinations (ids, not URLs). Otherwise: parse URL, allow only `http/https`, resolve DNS, reject private/loopback/link-local/multicast/reserved ranges (IPv4, IPv6, IPv4-mapped IPv6, decimal/octal/hex forms — compare parsed IPs, not strings), **connect to the validated IP** (prevents DNS rebinding), disable automatic redirects or re-validate each hop, set timeouts and response size limits, don't return raw responses/errors to the client. Infra: block metadata endpoints (IMDSv2 required, hop-limit 1), egress network policy.
- **Variants:** webhooks, URL previews/unfurlers, image-by-URL, PDF renderers (headless Chrome loading user HTML), XML parsers (XXE), import-from-URL, OAuth `jwks_uri`/`request_uri`.

## XXE (CWE-611)
- Disable DTDs/external entities (`defusedxml` in Python, `FEATURE_SECURE_PROCESSING` + disallow-doctype-decl in Java, `libxml` `noent:false` in Node).

## Path traversal & file handling (CWE-22, 73)
- Prefer storing files by generated id and mapping id → path server-side. If names are needed: `path.resolve(base, name)` then verify `resolved.startsWith(base + path.sep)` (Python: `Path(base).joinpath(name).resolve().is_relative_to(base)`); reject absolute paths, NUL bytes; handle symlinks (`realpath`). Zip extraction: validate each entry (Zip Slip).

## File uploads (CWE-434)
- Allowlist types by **magic bytes** + extension; size and count limits at the server/proxy; random server-side names; store outside web root or in a bucket with no execute and private ACL; serve with correct `Content-Type`, `X-Content-Type-Options: nosniff`, and `Content-Disposition: attachment` for non-images (or a separate sandbox domain); re-encode images (strips polyglots/EXIF); treat SVG/HTML as active content (sanitize or serve as attachment); AV scan if the risk model warrants; signed, expiring URLs for private files.

## Open redirect (CWE-601)
- Only relative paths starting with a single `/` (reject `//`, `/\`, schemes), or an allowlist of hosts; parse with a URL parser.

## Sensitive data exposure (CWE-200, 209, 312, 359, 532)
- Response DTOs/serializers that allowlist output fields (no password hashes, tokens, internal flags, other users' PII); generic error messages in production + correlation id; no stack traces; remove debug endpoints/source maps from prod builds (or restrict); don't log secrets/tokens/PII (redaction in logger); encrypt sensitive data at rest where required; TLS everywhere + HSTS; `Cache-Control: no-store` on authenticated sensitive responses.

## Secrets management (CWE-798, 259, 321)
- Move to env vars / secret manager (Vault, AWS/GCP/Azure secret managers, Doppler, platform env). Add `.env.example` with placeholders, ensure `.env*` in `.gitignore`. Fail fast at startup if a required secret is missing — **never fall back to a hardcoded default secret**. Instruct rotation of every exposed secret; recommend history cleanup (`git filter-repo`) only as a complement to rotation. Add secret scanning (gitleaks/trufflehog) to CI/pre-commit. Frontend bundles must contain no server secrets (`NEXT_PUBLIC_`/`VITE_` vars are public by design).

## Input validation (CWE-20)
- Schema validation at every trust boundary (zod, joi, yup, class-validator, pydantic, marshmallow, Bean Validation, JSON Schema): types, lengths, ranges, formats, enums; reject unknown fields where practical. Validation is not a substitute for parameterization/encoding — it's an additional layer. Limit body size, array lengths, nesting depth; ReDoS-safe regexes (no nested quantifiers on input; use `re2` if user-controlled patterns).

## Business logic (CWE-840, 841, 362)
- Server computes authoritative values (price, discount, totals, permissions). Enforce state machines (can't ship an unpaid order). Negative/zero/huge quantities rejected. Coupons/one-time actions: unique constraints + transactions/row locks/atomic updates to defeat race conditions (`UPDATE ... SET balance = balance - ? WHERE id=? AND balance >= ?`). Idempotency keys for payments. Rate limits on abusable features (invites, OTP, exports).

## Denial of service hygiene (in scope only as hardening)
- Body size limits, pagination caps, timeouts, query complexity/depth limits for GraphQL, disable introspection in prod if policy requires, rate limiting.

## Dependencies (CWE-1104, 1395)
- Run the ecosystem auditor; upgrade to the minimum fixed version first (patch/minor), test, then consider majors separately. Check whether the vulnerable function is actually reachable to prioritize, but still upgrade. Commit lockfiles; use `npm ci`/`--frozen-lockfile`; remove unused deps; pin GitHub Actions to SHAs; enable Dependabot/Renovate.
