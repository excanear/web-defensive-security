# Security Regression Testing & Re-attack

## Principles
- **Red first:** the security test must fail against the vulnerable code (proves it reproduces the finding), then pass after the fix. If you cannot make it fail first, the test does not cover the vulnerability — rework it.
- **Pair negative with positive:** every "attack is blocked" test has a sibling "legitimate use still works" test. This is how functionality preservation is proven.
- **Test at the right layer:** integration/HTTP-level tests for authz, CSRF, CORS, headers, cookies, injection through real routes; unit tests for validators, path/URL guards, sanitizers.
- **Name tests by finding id** (`WOS-003: rejects SQLi in search sort param`) so the report can link them and future regressions are traceable.
- Tests must use test fixtures/accounts and benign payloads; no real secrets, no external network.
- Keep them in the normal suite so CI runs them forever. Put shared payload lists in a fixture file.

## Stack patterns
- **Node/Express/Nest/Next API:** Jest/Vitest + `supertest` against the app instance (no listening port needed). Seed two users (A, B) and an admin.
- **Python:** pytest + Flask `test_client` / Django `Client` / FastAPI `TestClient`; `pytest.mark.parametrize` over payload lists.
- **Java/Spring:** `MockMvc` / `WebTestClient`, `@WithMockUser`.
- **PHP/Laravel:** Feature tests (`$this->actingAs($userB)->get(...)->assertForbidden()`).
- **Ruby/Rails:** request specs.
- **Go:** `httptest.NewRecorder` with the router.
- **Frontend XSS:** component tests (Testing Library) asserting payload renders as text (`getByText('<img src=x onerror=...>')`) and no element is created; e2e (Playwright) for DOM XSS asserting no dialog fires / marker global not set.
- **No framework:** a script in `security-audit/regression/` (bash+curl or a small node/python script) that exits non-zero if the exploit succeeds, documented in the report.

## Templates by class (adapt names)
- **IDOR:** user B GETs/PUTs/DELETEs user A's resource → 404/403 and A's data unchanged; user A → 200.
- **Function-level authz:** normal user calls admin endpoint → 403; admin → 200; unauthenticated → 401.
- **Mass assignment:** PATCH profile with `{"role":"admin","name":"x"}` → name updated, role unchanged.
- **SQLi:** payloads in each param (`' OR '1'='1`, `1;SELECT pg_sleep(0)`, `name) --`, sort=`(CASE WHEN 1=1 THEN name ELSE id END)`) → 400 or literal no-match, never extra rows/500; legit value with apostrophe (`O'Brien`) still works.
- **NoSQLi:** `{"username":{"$ne":null},"password":{"$ne":null}}` → 400/401.
- **XSS:** stored payload round-trip; response HTML contains encoded form (`&lt;script&gt;`), not raw.
- **Command injection:** input `x; echo PWNED` / `$(id)` / `-o/tmp/x` → rejected or treated as literal; assert spawned process args via mock if needed.
- **Path traversal:** `../../etc/passwd`, `..%2f..%2f`, `....//`, absolute `/etc/passwd`, `C:\Windows\win.ini`, NUL byte → 400/404; valid file name → 200.
- **SSRF:** `http://127.0.0.1`, `http://[::1]`, `http://169.254.169.254/`, `http://2130706433`, `http://0x7f000001`, `http://[::ffff:127.0.0.1]`, redirect to internal, DNS name resolving to private IP (mock resolver) → blocked; allowlisted public URL (mocked HTTP) → OK.
- **Upload:** `.php`/`.html`/`.svg` with image extension, polyglot, oversize, `../` filename → rejected/renamed; valid PNG → accepted and served with safe headers.
- **JWT:** `alg:none`, HS256 signed with public key, expired token, wrong `aud`/`iss`, tampered payload → 401; valid → 200.
- **CSRF:** state-changing request with session cookie but no/invalid token or foreign `Origin` → 403; with token → 200.
- **CORS:** `Origin: https://evil.example` → no `Access-Control-Allow-Origin` echo; allowed origin → echoed with `Vary: Origin`.
- **Headers/cookies:** assert presence/values of security headers and cookie flags on key responses.
- **Brute force:** N+1 failed logins → 429/lockout; correct login after window works.
- **Business logic/race:** negative quantity rejected; client-sent price ignored; concurrent coupon redemption (Promise.all of 10) → exactly one success.
- **Data exposure:** responses do not contain `password`, `passwordHash`, tokens, other tenants' records; production error returns generic body.
- **Secrets:** test/CI step running a secret scanner on the repo (gitleaks) if available.

## Re-attack bypass checklist (Phase 3 step 6 and Phase 5)
- Encoding: URL, double URL, Unicode/overlong, HTML entities, mixed case, whitespace/comment variants (`/**/`), null bytes.
- Transport variants: JSON vs form vs multipart vs XML content types; query vs body vs header vs cookie for the same param; HTTP parameter pollution (`?id=1&id=2`); arrays/objects where scalars expected.
- Method/route variants: `X-HTTP-Method-Override`, HEAD/OPTIONS, trailing slash, case in path, `/api/v1` vs `/api/v2`, GraphQL alias/batching, websocket path to same logic, export/bulk endpoints.
- Auth variants: no token, other user's token, expired token, downgraded role, token from another tenant.
- Race: concurrent requests on one-time operations.
- Second-order: payload stored safely but used unsafely later (admin views, emails, exports, background jobs, logs viewers).
- Variant hunting: grep the whole repo for the same dangerous API/pattern that caused the finding and confirm each occurrence is safe.
