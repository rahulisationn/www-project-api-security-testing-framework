<!-- AI-Generated Code - 2026-11-25 - Auto. This is AI generated content. -->

# OWASP API Security Testing Framework (ASTF): gap analysis

Reviewed: [OWASP/www-project-api-security-testing-framework](https://github.com/OWASP/www-project-api-security-testing-framework), `main` at `f8657be` (2026-11-22) and release `v2.0.2`.

ASTF is a black-box Java scanner with 16 test cases mapped to the OWASP API Security Top 10 2023, plus GraphQL, gRPC, mTLS, LLM, SQL/NoSQL injection and ReDoS. Its methodology guide is `docs/TESTING_GUIDELINES.md`. This review covers both the code and the guide.

Defects marked **live** were reproduced by running the released `astf-v2.0.2.jar` against the mock API in [`lab/`](lab/). Run `lab/run.sh` to repeat both scans.

## Summary

- **10 defects** in existing checks or guidance, **6 reproduced live**.
- **20 proposed tests** for techniques ASTF does not cover today, **5 of them Critical**.
- The most urgent issue is a responsible-testing problem. The BOLA check sends real `DELETE` and `PUT` requests to object IDs the tester does not own. On a stateful API it also misses the vulnerability it was looking for.

## 1. Defects in existing checks and guidance

| ID | Where | Defect | Evidence |
|---|---|---|---|
| D1 | `BrokenObjectLevelAuthorizationTestCase` :132, :180-188 | BOLA check is destructive and misses stateful bugs | **Live.** Stateful mock where anyone can `DELETE` any item: 0 findings, and objects 1, 2, 100, 999 and 0 were deleted |
| D2 | `HttpClient` :101 | Redirects are always followed, so the open-redirect check can never fire | **Live.** Mock returned `302` to the attacker host on all 9 probes: 0 findings |
| D3 | `SecurityMisconfigurationTestCase` :208, `ImproperInventoryManagementTestCase` :166 | Debug-endpoint and docs probes only run if a `/` endpoint exists | **Live.** Mock exposes `/actuator/env` and `/openapi.json`: 0 probes sent |
| D4 | `UnrestrictedAccessToSensitiveFlowsTestCase` :86, :97 | API6 reports HIGH on endpoints that reject every request | **Live.** Endpoint returning `422` every time: HIGH finding |
| D5 | `BrokenObjectPropertyLevelAuthorizationTestCase` :131 | Mass assignment drops required fields | **Live.** Register endpoint that echoes `isAdmin` when `username` and `password` are present: missed |
| D6 | `BrokenObjectLevelAuthorizationTestCase` :280-286 | BOLA sends `GET` for `PATCH` endpoints | **Live.** PATCH-only endpoint: the second identity sent `GET`, got `405`, missed |
| D7 | `BrokenObjectLevelAuthorizationTestCase` :135-138 | Cross-user BOLA compares status codes only | Code review |
| D8 | `UnsafeConsumptionOfApisTestCase` :41-42, :127 | Template-injection payload can never produce a finding | Code review |
| D9 | `SecurityMisconfigurationTestCase` :31-37 | Header policy contradicts OWASP guidance | Code review |
| D10 | `ServerSideRequestForgeryTestCase` :168 | SSRF body probe discards the real request body | Code review |

**D1. BOLA check is destructive and misses stateful bugs.** `testNumericIdManipulation` and `testUuidManipulation` replay the endpoint's own method against substituted IDs `1, 2, 100, 999, 0`. For `DELETE` and `PUT` endpoints, that deletes or overwrites objects belonging to other users. `testCrossUserAccess` also sends the primary identity's request first. On a `DELETE`, that destroys the object, so the secondary identity gets `404` and nothing is reported. Fix: never substitute IDs on state-changing methods by default. Prove cross-user access with `GET` against the same object. Put destructive confirmation behind an explicit `--allow-destructive` flag that only acts on resources the scan created itself: the primary identity creates the object, the secondary identity attempts the `PUT` or `DELETE`, then the primary identity reads the object back. Never act on hardcoded IDs. The Responsible Testing section should name this behaviour. **D1 depends on D7.** A `GET`-based cross-user check reports every public or shared object as CRITICAL unless the response bodies are compared, so ship the two fixes together.

**D2. Redirects are always followed.** `HttpClient` hard-codes `followRedirects(true)`, and `ScanConfig.isFollowRedirects()` is never read. `testOpenRedirect` requires `response.isRedirect()`, so it can never fire. The unit test passes only because it mocks `HttpClient`. Following redirects also turns `302 → /login` into a `200`, which can produce false "Missing Authentication" and admin-path findings. Fix: use a non-following client for probes, and honour the existing config option.

**D3. Debug and docs probes need a `/` endpoint.** Both probes return early unless `endpoint.getPath()` is `/`. None of `--endpoints-file`, spec discovery or the fallback list adds `/`. The guide recommends `--endpoints-file --no-discovery` as the highest-value mode, and in that mode these probes never run. Fix: run per-target probes once per base URL, keyed in the scanner, not on the presence of a root endpoint.

**D4. API6 false positive and documentation mismatch.** `testAutomatedAbuse` counts `422` as success, and defaults the body to `{}`. An endpoint that rejects every request with a validation error is therefore reported HIGH. The guide says API6 covers login, OTP, payment and password reset, and that body-level throttle messages are recognised. `SENSITIVE_FLOW_PATTERNS` contains no `login`, `password`, `reset` or `forgot`, and API6 never checks body markers. Substring matching (`pay`, `rate`, `like`, `share`) also matches unrelated paths such as `/players` or `/separate`.

**D5. Mass assignment drops required fields.** Payloads contain only the privileged keys, for example `{"isAdmin":true,"role":"admin"}`. Endpoints with required fields return `400`, so this check misses VAmPI's documented register mass assignment (`TRACEABILITY.md` VAmPI row 4). The guide lists `credit` among the injected fields, but no payload includes it. Fix: merge the privileged keys into the endpoint's discovered or configured body, then confirm with a follow-up `GET`.

**D6. BOLA sends `GET` for `PATCH` endpoints.** `makeRequest` has no `PATCH` case and falls through to `GET`.

**D7. Cross-user BOLA compares status codes only.** If both identities get `2xx` on the same URL, ASTF reports CRITICAL "Cross-User Access Confirmed". That is also true for shared or public objects, such as a public book catalogue. Fix: report a finding only when all three hold:
1. The secondary identity's response contains identifying fields from the primary identity's object, such as `id`, `owner_id` or `email`.
2. It differs from what the secondary identity gets for its own objects.
3. It differs from the unauthenticated response. If an anonymous caller gets the same body, the object is public, which is not a BOLA finding.

This check becomes mandatory once D1 moves cross-user testing to `GET`.

**D8. Template-injection payload can never fire.** `{{7*7}}` and `${7*7}` expect `49`, but `49` is explicitly excluded from matching to avoid false positives. Use a product that does not occur naturally, for example `1337*1337`, which evaluates to `1787569`. Only report it when `1787569` is absent from the baseline response.

The current payloads only cover `{{...}}` (Jinja2, Twig) and `${...}` (Spring EL, JSP EL, FreeMarker, Velocity). Send the same arithmetic in the other common syntaxes:

| Payload | Engines |
|---|---|
| `{{1337*1337}}` | Jinja2, Twig, Nunjucks |
| `${1337*1337}` | FreeMarker, Spring EL, JSP EL, Velocity, Groovy |
| `<%= 1337*1337 %>` | ERB (Ruby), EJS |
| `#{1337*1337}` | Ruby string interpolation, Pug, legacy FreeMarker numeric interpolation, Spring `@Value` |
| `*{1337*1337}`, `[[${1337*1337}]]` | Thymeleaf |
| `{1337*1337}` | Smarty |
| `@(1337*1337)` | Razor (.NET) |

Handlebars and Mustache are logic-less and do no arithmetic, so this probe can't detect them. Leave them to a separate syntax-error probe. FreeMarker's current syntax is `${...}`; `#{...}` is its deprecated numeric interpolation and works only on older templates.

**D9. Header policy contradicts OWASP guidance.** `X-XSS-Protection` is treated as a required header. The OWASP Secure Headers Project says to omit it or send `0`. `Cache-Control: no-store` on authenticated responses, which the OWASP REST Security Cheat Sheet recommends, is not checked. Fix:
- Remove `X-XSS-Protection` from `REQUIRED_SECURITY_HEADERS`. Report it at LOW only when it is present with a value other than `0`, because `1; mode=block` can introduce XS-Leak side channels in legacy browsers.
- Add a check that responses to authenticated requests carry `Cache-Control: no-store`.

**D10. SSRF body probe discards the real body.** The probe replaces the whole body with a single field such as `{"url":"..."}`, so request validation fails before the URL is used. It also looks only at top-level fields. The GCP and Azure metadata services reject requests that lack the `Metadata-Flavor: Google` or `Metadata: true` header. Their error text, for example "Missing Metadata-Flavor:Google header", proves the server reached the metadata endpoint, but those strings are not in `SSRF_INDICATORS`.

## 2. Proposed tests

| ID | OWASP | Test | Risk | Needs |
|---|---|---|---|---|
| ASTF-API1-04 | API1 | Object IDs in query, body and headers | Critical | Existing tokens |
| ASTF-API1-05 | API1 | Collection and search leakage | High | Existing tokens |
| ASTF-API2-12 | API2 | Signature not verified at all | Critical | Existing token |
| ASTF-API2-13 | API2 | Weak HMAC signing secret | High | Existing token, offline |
| ASTF-API2-14 | API2 | Token lifecycle and audience | High | Multi-step flow (#103), `--foreign-token` |
| ASTF-API3-03 | API3 | Write-then-read property authorization | High | Existing tokens |
| ASTF-API4-05 | API4 | Payload size and structure limits | High | None |
| ASTF-API4-06 | API4 / API6 | Rate-limit bypass | High | None |
| ASTF-API6-03 | API6 | Race condition and limit overrun | High | Opt-in flag |
| ASTF-API5-04 | API5 | Role matrix replay | Critical | `--admin-token` |
| ASTF-API5-05 | API5 | Gateway ACL bypass by override and normalization | High | None |
| ASTF-API7-02 | API7 | Blind SSRF and filter bypass | Critical | `--oast-domain` |
| ASTF-API8-06 | API8 | CORS origin-validation bypass | High | None |
| ASTF-API8-07 | API8 | Content-type confusion and XXE | High | `--oast-domain` for blind XXE |
| ASTF-API9-03 | API9 | Security-control parity across versions | High | Existing tokens |
| ASTF-API10-03 | API10 | Inbound webhook signature verification | Critical | None |
| ASTF-API10-04 | API10 | Hostile upstream responses | High | `--mock-upstream` |
| ASTF-GQL-14 | GraphQL | GraphQL authorization, CSRF and subscriptions | High | Existing tokens |
| ASTF-LLM-02 | LLM Top 10 | Indirect injection, leakage and excessive agency | High | Existing token |
| ASTF-INJ-05 | Injection | Time-based blind SQLi, OS command and SSTI on REST | High | None |

### API1-04. Object IDs in query, body and headers
**Gap:** All three BOLA techniques look only at path segments. Identifiers in the query string (`?user_id=`), the request body (`{"accountId": ...}`) and headers (`X-User-Id`, `X-Tenant-Id`) are never swapped, even when `--secondary-token` is set.
**Procedure:** Take identifiers from the primary identity's responses. Replay requests as the secondary identity with each identifier placed in each location.
**Pass:** The secondary identity gets `403` or `404`, and the response body never contains the primary identity's object.

### API1-05. Collection and search leakage
**Gap:** List and search endpoints are never compared across identities.
**Procedure:** Collect object IDs that only the secondary identity owns. Query the primary identity's collections with the owner filter left as is, removed, and swapped (`?owner=`, `?mine=true`).
**Pass:** None of the secondary identity's object IDs appear.

### API2-12. Signature not verified at all
**Gap:** ASTF forges `none`, `kid`, `jku` and RS256-to-HS256 tokens, but never corrupts the signature of the real token. That is the cheapest check and catches the most common bug: a server that decodes the token without verifying it.
**Procedure:** Flip one character in the signature segment of the configured token. Compare the result with the no-auth baseline that `probeWithoutAuth` already sends.
**Pass:** `401` on every authenticated endpoint.

### API2-13. Weak HMAC signing secret
**Gap:** `TRACEABILITY.md` marks VAmPI's weak signing key as N/A.
**Procedure:** For HS256, HS384 and HS512 tokens, try a bundled list of common JWT secrets against the operator's own token. This runs offline and sends no traffic to the target.
**Pass:** No secret in the list verifies the token.

### API2-14. Token lifecycle and audience
**Gap:** Nothing tests whether a token still works after logout or a password change, whether a refresh token can be reused, or whether a token issued for another service is accepted (`aud` and `iss` not enforced).
**Pass:** Revoked, rotated and foreign-audience tokens are all rejected.

### API3-03. Write-then-read property authorization
**Gap:** Mass assignment is judged only by whether the same response echoes the value. Persisted escalation and read-only fields (`id`, `owner_id`, `balance`, `email_verified`, `created_at`) are not tested.
**Procedure:** Merge the privileged keys into a valid body, write it, then read the object back with `GET`.
**Pass:** The stored object is unchanged in every privileged or read-only property.

### API4-05. Payload size and structure limits
**Gap:** API4 only counts `429` responses and requests large page sizes.
**Procedure:** Send oversized bodies, JSON nested 10,000 levels deep, very large arrays to bulk endpoints, and `expand` or `include` amplification parameters.
**Pass:** `413` or `400` with no response-time blow-up.

### API4-06. Rate-limit bypass
**Gap:** The check asks only whether a `429` ever appears.
**Procedure:** Once the endpoint starts returning `429`, rotate `X-Forwarded-For`, `X-Real-IP` and `True-Client-IP`. Also try path variants: changed case, a trailing slash, a `;param` suffix and `%2e`.
**Pass:** The endpoint stays rate-limited.

### API6-03. Race condition and limit overrun
**Gap:** One-time or bounded actions (coupon redemption, transfers, votes, invite codes) are never sent in parallel. This is the crAPI coupon class.
**Procedure:** Send N identical requests in a single packet. This changes state, so it should only run behind an opt-in flag.
**Pass:** Exactly one request succeeds.

### API5-04. Role matrix replay
**Gap:** BFLA detection relies on guessed admin paths and naming substitution.
**Procedure:** With `--admin-token`, discover the endpoints the admin token can reach. Replay each one with the low-privilege token and with no token.
**Pass:** `403` for the low-privilege token and `401` for no token, on every admin-only endpoint.

### API5-05. Gateway ACL bypass by override and normalization
**Procedure:** Send `X-HTTP-Method-Override`, `X-Original-URL` and `X-Rewrite-URL` headers. Try path variants such as `/admin/..;/`, `//admin` and `%2fadmin`.
**Pass:** Override headers are ignored, and each variant gets the same authorization decision as the canonical path.

### API7-02. Blind SSRF and filter bypass
**Gap:** SSRF detection is in-band only: the fetched content has to come back in the response. There is no OAST callback, no encoded addresses (decimal, hex, IPv4-mapped IPv6), no redirect to the metadata service and no DNS rebinding.
**Pass:** No DNS or HTTP interaction at the OAST domain for any URL-shaped field, and encoded internal addresses are rejected.

### API8-06. CORS origin-validation bypass
**Procedure:** Send `Origin: null`, suffix and prefix variants (`target.com.evil.com`, `eviltarget.com`) and a credentialed preflight request.
**Pass:** Only allowlisted origins are reflected, and `null` is never allowed with credentials.

### API8-07. Content-type confusion and XXE
**Procedure:** Send JSON endpoints an XML body with an external entity pointing at the OAST domain, and a form-encoded body.
**Pass:** `415` for the unexpected content types, and no OAST interaction.

### API9-03. Security-control parity across versions
**Gap:** An old version or `/beta` path is flagged only for being reachable. The real API9 risk is that it lacks controls the current version has. Header and query versioning (`Accept-Version`, `api-version=`) are never probed.
**Pass:** Unauthenticated and cross-user replays against older, beta and header-selected versions get the same denial as the current version.

### API10-03. Inbound webhook signature verification
**Gap:** The webhook check fuzzes strings into webhook-named paths. It never asks whether `/webhooks/*` accepts an unsigned event.
**Procedure:** Send provider-shaped events (Stripe, GitHub, Slack) with the signature header missing, stale or wrong.
**Pass:** Every such event is rejected.

### API10-04. Hostile upstream responses
**Gap:** API10 is about an API trusting a third party's responses, but ASTF only fuzzes the API's own input.
**Procedure:** Register a callback or import URL that points at a tester-controlled upstream. The upstream redirects to `169.254.169.254`, returns oversized or slowly dripped bodies, and presents an invalid certificate.
**Pass:** The API refuses the redirect, enforces size and time limits, and validates the upstream certificate.

### GQL-14. GraphQL authorization, CSRF and subscriptions
**Gap:** `--secondary-token` is never used against GraphQL.
**Procedure:** Make cross-user `node(id:)` and object lookups. Send mutations over `GET` and as form-encoded `POST` (the CSRF case). Open WebSocket subscriptions without credentials.
**Pass:** Cross-user lookups are denied, mutations are rejected over `GET` and non-JSON content types, and subscriptions require auth at `connection_init`.

### LLM-02. Indirect injection, leakage and excessive agency
**Gap:** ASTF has one direct canary check, sent in a single-field body.
**Procedure:** Plant instructions in stored content that the model later reads (indirect injection, OWASP LLM01). Try to extract the system prompt. Check whether the model can trigger state-changing API actions. Check whether model output is unsafe, for example markdown image exfiltration.
**Pass:** Stored instructions are not followed, the system prompt is not disclosed, tool calls require user intent, and output is encoded.

### INJ-05. Time-based blind SQLi, OS command and SSTI on REST
**Gap:** SQL injection detection is error-based plus a heuristic on unexpected `500` responses. OS-command and template payloads exist only for GraphQL resolvers.
**Procedure:** Send `pg_sleep`, `SLEEP` and `WAITFOR` payloads, plus OS-command and template payloads, to REST fields.
**Pass:** No payload-correlated delay across 3 repeated samples, and no command or template evaluation markers.

## 3. Suggested pull request order

1. D1 together with D7, then D2. D1 deletes other users' data during an authorized scan, and its GET-based fix needs D7's body comparison to avoid false Criticals. D2 silently disables a whole check.
2. D3, D4, D5 and D6. Each is confirmed against a mock and has a small, local fix.
3. API2-12, API10-03, API1-04 and API5-04. Highest impact, with little or no new scanner capability.
4. API7-02 and API8-07, behind one shared `--oast-domain` option.
5. D8 to D10, then the remaining tests.

## Reproducing the live findings

Requirements: Java 21+, Python 3.10+ (standard library only) and curl. From this directory, run:

```bash
./lab/run.sh
```

The script downloads `astf-v2.0.2.jar` if it is missing, starts the mock API on `127.0.0.1:47811` (set `MOCK_PORT` to change it), and runs two scans. Reports, logs and the exact requests ASTF sent are written to `lab/out/`. The mock API only listens on loopback.
