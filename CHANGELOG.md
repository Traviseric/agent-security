# Changelog

## [2.0.0] - 2026-02-17

### Added

**30 New Detection Patterns (190 → 220)**

- **Infrastructure attack patterns** (`src/patterns/infrastructure.ts` — 18 patterns)
  - Environment variable injection: LD_PRELOAD, DYLD_INSERT_LIBRARIES, LD_LIBRARY_PATH, PATH override
  - Symlink traversal: symlink creation outside sandbox, file read without lstat
  - Windows exec evasion: cmd.exe command chaining, PowerShell -EncodedCommand, cmd pipe chaining
  - Network/fetch misconfig: missing timeout, missing body size limit, missing content-length check
  - Extended SSRF: link-local (169.254.x.x), CGNAT (100.64.x.x), IPv6-mapped (::ffff:), IPv6 loopback (::1)
  - Bind/proxy misconfig: 0.0.0.0/:: binding, unvalidated X-Forwarded-For headers

- **Auth anti-patterns** (added to `rce.ts` — 4 patterns)
  - Fail-open catch blocks (`catch { return true }`)
  - String "undefined" comparison (JS coercion bypass)
  - Partial identity matching (startsWith/includes on userId/email)
  - Non-constant-time secret/token/HMAC comparison (timing attack)

- **Supply chain install patterns** (added to `defense-evasion.ts` — 4 patterns)
  - curl pipe to shell in docs
  - wget pipe to shell in docs
  - PowerShell download-and-execute in docs
  - Password-protected archive instructions (antivirus evasion)

- **Container misconfiguration patterns** (added to `defense-evasion.ts` — 4 patterns)
  - Home directory bind mount ($HOME, /home/, /root/, /Users/)
  - Root filesystem mount (/:/host)
  - Seccomp unconfined
  - AppArmor unconfined

**5 Runtime Guard Modules** (`src/guards/`)

- **SSRF Guard** (`ssrf.ts`) — DNS pinning, IP blocklists (RFC 1918, loopback, link-local, CGNAT, IPv6), hostname blocks, redirect validation
- **Download Guard** (`download.ts`) — body size caps, connection/response timeouts, content-type validation, streaming size enforcement
- **Exec Allowlist** (`exec-allow.ts`) — default-deny execution, resolved binary path matching, env var filtering (LD_PRELOAD, DYLD_*), cmd.exe/PowerShell evasion detection
- **Path Traversal Validator** (`fs-safe.ts`) — TOCTOU-safe file open within root boundary, symlink validation, post-open inode verification, null byte detection
- **Webhook Verifier** (`webhook.ts`) — timing-safe HMAC verification for GitHub, Slack, Stripe webhooks + generic HMAC factory

**New Exports**

- `@empowered-humanity/agent-security/guards` — barrel export for all guard modules
- `@empowered-humanity/agent-security/guards/ssrf` — SSRF guard
- `@empowered-humanity/agent-security/guards/download` — download guard
- `@empowered-humanity/agent-security/guards/exec-allow` — exec allowlist
- `@empowered-humanity/agent-security/guards/fs-safe` — path traversal validator
- `@empowered-humanity/agent-security/guards/webhook` — webhook verifier

**New Type System Entries**

- Source IDs: OPENCLAW-CAT1 through CAT8, CLAWHAVOC, GEMINI-OPENCLAW
- Attack categories: env_injection, timing_attack, container_misconfig, supply_chain_install

**Tests**

- 254 tests passing (was 123)
- New test files: infrastructure, auth-antipatterns, supply-chain, guards-ssrf, guards-download, guards-exec, guards-fs-safe, guards-webhook

### Changed

- Package description updated to reflect runtime guard capabilities
- README updated with guard module documentation, new pattern categories, and usage examples
- Console reporter: fixed chalk function call syntax for OWASP compliance and taint proximity output

### Research Foundation

All new patterns and modules trace to specific research findings:
- OpenClaw vulnerability catalog (80+ security commits, 12 vulnerability categories)
- ClawHavoc supply chain campaign (341 malicious skills in ClawHub marketplace)
- Gemini deep research analysis (45 sources, 8 CVEs)
- AI Agent Security Fundamentals + Best Practices

---

## [1.2.0] - 2026-02-10

- SARIF reporter with CWE mappings
- Intelligence engine: auto-classification, taint proximity analysis, context flow tracing
- MCP checklist patterns (SlowMist — 44 patterns, 9 categories)
- 190 total patterns
- Published to npm

## [1.1.0] - 2026-02-07

- OWASP ASI full mapping (ASI01-ASI10, 65 patterns)
- Defense evasion patterns
- Context-aware pattern filtering
- Test file severity downgrade

## [1.0.0] - 2026-02-03

- Initial release
- 90 detection patterns
- CLI with scan, patterns, stats commands
- Console and JSON output
- GitHub Action integration
