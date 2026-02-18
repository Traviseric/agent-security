# Agent Security v2.0 Implementation Plan

**Created:** 2026-02-17
**Status:** Phases 1-5, 8 Complete ✅ (patterns + all guard modules built)
**Current:** 220 patterns, 5 runtime guard modules, 254 tests passing
**Target:** v2.0.0 release (npm publish, public repo sync)

---

## Research Foundation

This plan is derived from three research documents and their gap analyses:

| Document | Location | What It Contributes |
|----------|----------|-------------------|
| AI Agent Security Fundamentals | `docs/research/ai agents/AI_AGENT_SECURITY_FUNDAMENTALS.md` | Theoretical basis: von Neumann "original sin," Lethal Trifecta, halting problem, vendor defense critique |
| OpenClaw Git Analysis (80+ commits) | `docs/research/ai agents/OPENCLAW_SECURITY_ANALYSIS.md` | 80+ commit-level vulnerability catalog, source code patterns (ssrf.ts, fs-safe.ts, exec-approvals.ts), formal verification, gap analysis tables |
| OpenClaw Gemini Deep Research (45 sources) | `C:\code\ai-assistant\docs\research\security\OpenClaw AI Security Analysis.md` | 8 CVEs, ClawHavoc supply chain attack (341 malicious skills), Moltbook breach (35K emails + 1.5M tokens), Reader-Executor isolation pattern, comparative analysis |
| AI Agent Security Best Practices | `docs/research/ai agents/AI_AGENT_SECURITY_BEST_PRACTICES.md` | 6-layer defense-in-depth model, code templates, architecture checklist, approval gate patterns, risk score formula |

**Key research insight:** Our agent-security already leads on AI-layer detection (prompt injection, CAPE, MCP, RAG poisoning — things OpenClaw doesn't have). But OpenClaw's infrastructure-layer hardening (SSRF, path traversal, sandbox escape, exec allowlists, formal verification) reveals gaps we should close. Closing them turns agent-security from a static scanner into a runtime security library.

---

## Architecture: v1 vs v2

### v1 (Current) — Static Pattern Scanner

```
@empowered-humanity/agent-security
├── src/patterns/     190 detection patterns (regex-based)
├── src/scanner/      Pattern matching engine (context-aware, taint analysis)
├── src/reporters/    Console, JSON, SARIF output
└── CLI + GitHub Action + pre-commit hook
```

### v2 (Target) — Static Scanner + Runtime Guards

```
@empowered-humanity/agent-security
├── src/patterns/     220+ detection patterns (30+ new from OpenClaw research)
├── src/scanner/      Pattern matching engine (unchanged)
├── src/reporters/    Console, JSON, SARIF (unchanged)
├── src/guards/       ← NEW: Runtime security modules
│   ├── ssrf.ts           SSRF protection (DNS pinning, IP blocklists)
│   ├── fs-safe.ts        Path traversal prevention (TOCTOU-safe)
│   ├── exec-allow.ts     Exec allowlist (default-deny, resolved paths)
│   ├── download.ts       Download guard (size caps, timeouts)
│   └── webhook.ts        Webhook verification (timing-safe HMAC)
└── CLI + GitHub Action + pre-commit hook
```

**Import paths for consumers:**
```typescript
// Static scanning (existing)
import { ALL_PATTERNS, matchPatterns, calculateRiskScore } from '@empowered-humanity/agent-security';

// Runtime guards (new)
import { createSsrfGuard } from '@empowered-humanity/agent-security/guards/ssrf';
import { openFileWithinRoot } from '@empowered-humanity/agent-security/guards/fs-safe';
import { createExecAllowlist } from '@empowered-humanity/agent-security/guards/exec-allow';
import { createDownloadGuard } from '@empowered-humanity/agent-security/guards/download';
import { verifyWebhookSignature } from '@empowered-humanity/agent-security/guards/webhook';
```

---

## Phase 1: New Detection Patterns

**Goal:** Extend pattern library from 190 to ~220+ patterns covering infrastructure-layer gaps identified by OpenClaw research.

**Effort:** 1-2 sessions
**Files modified:** Existing pattern files + 1-2 new files

### 1A. Infrastructure Attack Patterns (new file: `src/patterns/infrastructure.ts`)

Source: OpenClaw vulnerability catalog categories 1-6

| Pattern Name | Category | Severity | What It Detects | OpenClaw Source |
|---|---|---|---|---|
| `env_ld_preload` | `code_injection` | critical | `LD_PRELOAD=` in env/command context | Cat 3 #4 |
| `env_dyld_inject` | `code_injection` | critical | `DYLD_INSERT_LIBRARIES`, `DYLD_*` | Cat 3 #4 |
| `env_ld_library_path` | `code_injection` | high | `LD_LIBRARY_PATH=` override | Cat 3 #4 |
| `env_path_override` | `code_injection` | high | `PATH=` override in exec context | Cat 3 #3 |
| `symlink_create` | `path_traversal` | high | `ln -s` targeting outside sandbox | Cat 1 #6 |
| `symlink_readlink` | `path_traversal` | medium | Missing lstat/readlink before open | Cat 1 #6 |
| `win_cmd_chain` | `code_injection` | critical | `cmd.exe /c "safe & evil"` | Cat 3 #7 |
| `win_powershell_encoded` | `code_injection` | critical | `powershell -EncodedCommand` | Cat 3 #7 |
| `win_cmd_pipe` | `code_injection` | high | `cmd /c "safe \| evil"` | Cat 3 #7 |
| `fetch_no_timeout` | `config_vulnerability` | medium | `fetch()` / `axios` without timeout config | Cat 6 |
| `fetch_no_size_limit` | `config_vulnerability` | medium | HTTP request without `maxContentLength` | Cat 6 |
| `dns_rebind_indicator` | `ssrf` | high | Multiple DNS resolutions to same host | Cat 2 #3 |
| `bind_all_interfaces` | `config_vulnerability` | high | `0.0.0.0` or `::` in listen/bind | Cat 4 #1 |
| `reverse_proxy_unvalidated` | `config_vulnerability` | high | `X-Forwarded-For` used without trusted proxy config | Cat 4 #1 |
| `ssrf_link_local` | `ssrf` | critical | `169.254.x.x` (link-local) in URL | Cat 2 |
| `ssrf_cgnat` | `ssrf` | high | `100.64.x.x` (CGNAT) in URL | Cat 2 |
| `ssrf_ipv6_mapped` | `ssrf` | critical | `::ffff:127.0.0.1` IPv6-mapped localhost | Cat 2 |
| `ssrf_ipv6_loopback` | `ssrf` | critical | `::1` IPv6 loopback | Cat 2 |

### 1B. Auth Anti-Pattern Detection (add to existing files)

Source: OpenClaw vulnerability catalog category 4

| Pattern Name | Target File | Severity | What It Detects | OpenClaw Source |
|---|---|---|---|---|
| `auth_fail_open_catch` | `rce.ts` | critical | `catch { return true }` or `catch { allow }` in auth | Cat 4 #8 |
| `auth_string_undefined` | `rce.ts` | critical | Comparison with string `"undefined"` | Cat 4 #4 |
| `auth_partial_match` | `injection.ts` | high | `.startsWith()` or `.includes()` on identity checks | Cat 4 #10 |
| `timing_unsafe_compare` | `credentials.ts` | high | `=== secret` / `== token` (not timingSafeEqual) | Cat 8 |

### 1C. Supply Chain / Marketplace Patterns (add to `defense-evasion.ts`)

Source: Gemini Deep Research — ClawHavoc campaign

| Pattern Name | Severity | What It Detects | Source |
|---|---|---|---|
| `readme_curl_pipe_sh` | critical | `curl \| sh` or `curl \| bash` in README/docs | ClawHavoc |
| `readme_powershell_download` | critical | `powershell -c "Invoke-WebRequest...` in README | ClawHavoc |
| `readme_password_zip` | high | Instructions to download password-protected archives | ClawHavoc |
| `readme_manual_init_step` | medium | "Run this initialization command" in skill/plugin docs | ClawHavoc |
| `docker_home_mount` | critical | Bind mount of `$HOME`, `/home`, or `/` into container | Gemini anti-patterns |
| `docker_host_network` | critical | `--network host` or `network_mode: host` | Gemini anti-patterns |
| `seccomp_unconfined` | critical | `security_opt: seccomp:unconfined` | Gemini anti-patterns |
| `apparmor_unconfined` | critical | `security_opt: apparmor:unconfined` | Gemini anti-patterns |

### 1D. Type System Updates (`src/patterns/types.ts`)

New source IDs needed:
```typescript
// Add to SourceId type
| 'OPENCLAW-CAT1'   // Path traversal (7 vulns)
| 'OPENCLAW-CAT2'   // SSRF (5 vulns)
| 'OPENCLAW-CAT3'   // Exec/sandbox escape (8 vulns)
| 'OPENCLAW-CAT4'   // Auth/access control (10 vulns)
| 'OPENCLAW-CAT6'   // DoS (4 vulns)
| 'OPENCLAW-CAT8'   // Timing attacks (2 vulns)
| 'OPENCLAW-CAT11'  // Tool/plugin security (5 vulns)
| 'CLAWHAVOC'       // Supply chain campaign
| 'GEMINI-OPENCLAW' // Gemini deep research
```

New attack categories needed:
```typescript
// Add to AttackCategory type
| 'env_injection'         // LD_PRELOAD, DYLD_*, PATH override
| 'timing_attack'         // Non-constant-time comparison
| 'container_misconfig'   // Docker/K8s security misconfigurations
| 'supply_chain_install'  // Malicious install instructions in docs
```

### 1E. Test Coverage

Each new pattern group gets a test file or section:

| Test Area | File | Patterns Tested |
|---|---|---|
| Infrastructure patterns | `tests/infrastructure.test.ts` | All 18 from 1A |
| Auth anti-patterns | `tests/auth-antipatterns.test.ts` | All 4 from 1B |
| Supply chain patterns | `tests/supply-chain.test.ts` | All 8 from 1C |
| Regression | `tests/patterns.test.ts` | Ensure existing 190 patterns unaffected |

---

## Phase 2: SSRF Guard Module

**Goal:** Runtime SSRF protection importable by any app in the monorepo.
**Effort:** 1 session
**Reference:** OpenClaw `src/infra/net/ssrf.ts` (131 lines)
**New file:** `src/guards/ssrf.ts`

### Design

```typescript
interface SsrfPolicy {
  allowPrivateNetwork?: boolean;      // Default: false
  allowedHostnames?: string[];        // Explicit allowlist
  blockedHostnames?: string[];        // Additional blocks beyond defaults
  followRedirects?: boolean;          // Default: true (re-validates each hop)
  maxRedirects?: number;              // Default: 5
  pinDns?: boolean;                   // Default: true (anti-rebinding)
}

interface SsrfGuard {
  validateUrl(url: string): Promise<SsrfResult>;
  createPinnedFetch(url: string): Promise<Response>;
}

// Usage:
const guard = createSsrfGuard({ allowedHostnames: ['api.github.com'] });
const result = await guard.validateUrl(userProvidedUrl);
if (!result.safe) throw new SsrfBlockedError(result.reason);
```

### Blocked by default

From OpenClaw's module:
- RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`, `::1`
- Link-local: `169.254.0.0/16`, `fe80::/10`
- CGNAT: `100.64.0.0/10`
- IPv6 private: `fc00::/7`
- IPv6-mapped: `::ffff:` prefix
- Hostnames: `localhost`, `*.localhost`, `*.local`, `*.internal`, `metadata.google.internal`, `169.254.169.254`

### DNS Pinning (anti-rebinding)

```
1. Resolve hostname to IP addresses
2. Check ALL resolved IPs against blocklist
3. Pin resolved IP for the actual connection
4. Prevent TOCTOU: DNS returns safe IP for check, malicious IP for connection
```

### Consumers

| App | Usage |
|-----|-------|
| `scraper-core` | Wrap all proxy/tor fetches |
| `osint-auditor` | Validate scan target URLs |
| `broker-removal` | Validate opt-out form submission endpoints |
| `vuln-scanner` | DAST module URL validation |

---

## Phase 3: Download Guard Module

**Goal:** Enforce size caps + timeouts on all external fetches.
**Effort:** Half session
**Reference:** OpenClaw Category 6 (DoS — 4 vulns)
**New file:** `src/guards/download.ts`

### Design

```typescript
interface DownloadPolicy {
  maxBodyBytes: number;          // Default: 10MB
  connectionTimeoutMs: number;   // Default: 10_000
  responseTimeoutMs: number;     // Default: 30_000
  allowedContentTypes?: string[]; // Optional: ['application/json', 'text/html']
}

interface DownloadGuard {
  fetch(url: string, options?: RequestInit): Promise<Response>;
  stream(url: string): AsyncIterable<Uint8Array>;
}
```

### Key behaviors

- Abort if `Content-Length` header exceeds `maxBodyBytes`
- Stream body and abort if accumulated size exceeds limit (for chunked responses)
- AbortController with connection + response timeouts
- Optional content-type validation (reject unexpected MIME types)

### Consumers

Same as SSRF Guard — wrap scraper-core and any direct fetch calls.

---

## Phase 4: Exec Allowlist Module

**Goal:** Default-deny exec with resolved binary path matching.
**Effort:** 1 session
**Reference:** OpenClaw `src/infra/exec-approvals.ts` (540+ lines)
**New file:** `src/guards/exec-allow.ts`

### Design

```typescript
type SecurityLevel = 'deny' | 'allowlist' | 'full';

interface ExecPolicy {
  securityLevel: SecurityLevel;       // Default: 'deny'
  safeBins: string[];                 // Default: ['jq', 'grep', 'cut', 'sort', 'uniq', 'head', 'tail', 'tr', 'wc']
  customAllowlist?: string[];         // Additional allowed binaries
  blockedEnvVars: string[];           // Default: ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'LD_LIBRARY_PATH']
  resolveBeforeMatch: boolean;        // Default: true (match resolved path, not user string)
}

interface ExecAllowlist {
  canExecute(command: string, args: string[], env?: Record<string, string>): ExecDecision;
  addToAllowlist(binary: string): void;
  removeFromAllowlist(binary: string): void;
}

interface ExecDecision {
  allowed: boolean;
  reason: string;
  resolvedPath?: string;         // Actual binary path after resolution
  blockedEnvVars?: string[];     // Which env vars were stripped
}
```

### Key behaviors

From OpenClaw's model:
1. Resolve binary to absolute path (prevents `/usr/bin/../evil` tricks)
2. Match resolved path against allowlist (not user-provided string)
3. Filter dangerous env vars before execution
4. Platform-specific evasion handling:
   - Windows: Block `cmd.exe /c "safe & evil"` chaining
   - Windows: Block `powershell -EncodedCommand`
   - Unix: Block `;`, `|`, `&&` in arguments when not using shell

### Consumers

| App | Usage |
|-----|-------|
| `pentest-toolkit` | Gate nmap/nuclei/nikto execution |
| Any app using `child_process` | Enforce allowlist before spawn |

---

## Phase 5: Path Traversal Validator

**Goal:** TOCTOU-safe file access within a root boundary.
**Effort:** 1 session
**Reference:** OpenClaw `src/infra/fs-safe.ts` (103 lines)
**New file:** `src/guards/fs-safe.ts`

### Design

```typescript
interface FsSafeOptions {
  root: string;                    // Sandbox root directory
  allowSymlinks?: boolean;         // Default: false
  followSymlinksInRoot?: boolean;  // Default: false (allow symlinks only within root)
}

// Core function:
async function openFileWithinRoot(
  root: string,
  relativePath: string,
  options?: FsSafeOptions
): Promise<FileHandle>

// Returns opened file handle ONLY if:
// 1. Resolved path starts with root + path.sep
// 2. lstat confirms not a symlink (unless allowed)
// 3. Post-open inode check matches (TOCTOU defense)
// 4. Target is a regular file (not directory, device, etc.)
```

### Platform handling

- Unix: Use `O_NOFOLLOW` flag on open
- Windows: Use `lstat()` → check `isSymbolicLink()` (no O_NOFOLLOW equivalent)
- Both: Post-open `fstat()` → compare `ino`/`dev` with `realpath` stat

---

## Phase 6: detect-secrets in CI

**Goal:** Automated secret scanning across the entire monorepo.
**Effort:** Half session
**Reference:** OpenClaw's 518-entry baseline + CI integration

### Implementation

1. Add `.secrets.baseline` file to repo root (generated by `detect-secrets scan`)
2. Add CI step to `.github/workflows/ci.yml`:
   ```yaml
   - name: Secret scanning
     run: |
       pip install detect-secrets
       detect-secrets scan --baseline .secrets.baseline
       detect-secrets audit --report --baseline .secrets.baseline
   ```
3. Add pre-commit hook (optional):
   ```yaml
   - repo: https://github.com/Yelp/detect-secrets
     hooks:
       - id: detect-secrets
         args: ['--baseline', '.secrets.baseline']
   ```

### Scope

Covers entire monorepo — all 8 apps + 2 packages.

---

## Phase 7: Cross-Scan vuln-scanner Rules

**Goal:** Port OpenClaw vulnerability patterns into vuln-scanner's SAST engine.
**Effort:** 1-2 sessions
**Files modified:** `apps/vuln-scanner/src/sast/`

### New SAST Rules

| Rule | OpenClaw Source | What It Detects |
|---|---|---|
| `path-traversal-unvalidated` | Cat 1 (7 vulns) | `fs.readFile(userInput)` without root-boundary validation |
| `ssrf-unvalidated-fetch` | Cat 2 (5 vulns) | `fetch(userInput)` without IP/hostname checks |
| `exec-shell-true` | Cat 3 (8 vulns) | `shell: true` + user input in command flow |
| `auth-fail-open` | Cat 4 (10 vulns) | `catch` blocks that return `true` / `allow` in auth code |
| `timing-unsafe-secret` | Cat 8 (2 vulns) | `===` comparison on secrets (should use timingSafeEqual) |
| `no-download-limit` | Cat 6 (4 vulns) | External fetch without body size cap |

### Integration

These rules import pattern definitions from `@empowered-humanity/agent-security` to avoid duplication — the patterns are defined once in agent-security, consumed by vuln-scanner's SAST engine.

---

## Phase 8: Webhook Verifier

**Goal:** Timing-safe HMAC verification for API webhooks.
**Effort:** Half session
**Reference:** OpenClaw `extensions/voice-call/src/webhook-security.ts`
**New file:** `src/guards/webhook.ts`

### Design

```typescript
interface WebhookVerifier {
  verify(payload: Buffer | string, signature: string, secret: string): boolean;
}

// Provider-specific:
function verifyGitHubWebhook(payload: string, signature: string, secret: string): boolean;
function verifySlackWebhook(payload: string, signature: string, timestamp: string, secret: string): boolean;
function verifyStripeWebhook(payload: string, signature: string, secret: string): boolean;

// All use crypto.timingSafeEqual() internally — never === for HMAC comparison
```

### Consumer

`osint-auditor` REST API (deployed at threatrecon.org) — verify incoming webhook callbacks.

---

## Phase 9: Release v2.0.0

**Goal:** Major version bump, update public repo, publish to npm.
**Effort:** Half session

### Checklist

- [ ] All new patterns have tests passing
- [ ] All guard modules have tests passing
- [ ] `src/guards/index.ts` barrel export created
- [ ] `package.json` exports map updated for `./guards/*` subpath exports
- [ ] README.md updated with guards documentation
- [ ] CHANGELOG.md written
- [ ] SBOM regenerated
- [ ] `npm publish` as `@empowered-humanity/agent-security@2.0.0`
- [ ] Sync to public repo via `tools/sync-public-repos.sh agent`
- [ ] GitHub release created with release notes

### Breaking changes

None expected — v2.0 is additive. Existing pattern scanning API unchanged. Guards are new exports only.

Bump to 2.0.0 because:
- New capability tier (runtime guards, not just static scanning)
- New exports (`/guards/*` subpath)
- Significant pattern count increase

---

## Cross-Platform Integration Map

How v2.0 modules integrate across the monorepo:

```
@empowered-humanity/agent-security v2.0.0
├── patterns/ (220+ patterns)
│   ├── Used by: vuln-scanner (SAST rules import)
│   ├── Used by: agent-security CLI (self-scan)
│   └── Used by: any CI/CD pipeline (GitHub Action)
│
├── guards/ssrf.ts
│   ├── Used by: scraper-core (all proxy/tor fetches)
│   ├── Used by: osint-auditor (scan target validation)
│   ├── Used by: broker-removal (form submission endpoints)
│   └── Used by: vuln-scanner DAST (target validation)
│
├── guards/download.ts
│   ├── Used by: scraper-core (size-limited fetches)
│   ├── Used by: osint-auditor (web content fetching)
│   └── Used by: broker-removal (page downloads)
│
├── guards/exec-allow.ts
│   ├── Used by: pentest-toolkit (nmap/nuclei gating)
│   └── Used by: any app with child_process usage
│
├── guards/fs-safe.ts
│   └── Used by: any app that reads user-specified paths
│
└── guards/webhook.ts
    └── Used by: osint-auditor REST API (webhook verification)
```

---

## Research Traceability

Every new pattern and module traces back to a specific research finding:

| Implementation | Research Doc | Section | Line(s) |
|---|---|---|---|
| Infrastructure patterns (18) | OPENCLAW_SECURITY_ANALYSIS.md | Vulnerability Catalog, Categories 1-6 | 37-175 |
| Auth anti-patterns (4) | OPENCLAW_SECURITY_ANALYSIS.md | Category 4: Auth/Access Control | 126-148 |
| Supply chain patterns (8) | OpenClaw Gemini Deep Research | ClawHavoc Campaign | Section on 341 malicious skills |
| SSRF Guard | OPENCLAW_SECURITY_ANALYSIS.md | Category 2 + Agent-Security NPM Gaps #1 | 66-93, 437-443 |
| Download Guard | OPENCLAW_SECURITY_ANALYSIS.md | Category 6 + NPM Gaps #5 | 166-175, 462-466 |
| Exec Allowlist | OPENCLAW_SECURITY_ANALYSIS.md | Category 3 + NPM Gaps #3 | 96-121, 450-456 |
| Path Traversal Validator | OPENCLAW_SECURITY_ANALYSIS.md | Category 1 + NPM Gaps #2 | 37-63, 444-449 |
| Webhook Verifier | OPENCLAW_SECURITY_ANALYSIS.md | Category 8 + NPM Gaps #4 | 196-201, 457-460 |
| detect-secrets CI | OPENCLAW_SECURITY_ANALYSIS.md | Category 10 | 216-225 |
| Risk score formula | AI_AGENT_SECURITY_BEST_PRACTICES.md | Quick Reference Cards | 657-664 |
| Lethal Trifecta model | AI_AGENT_SECURITY_FUNDAMENTALS.md | Why Agents Are Dangerous | 126-135 |
| Defense-in-depth layers | AI_AGENT_SECURITY_BEST_PRACTICES.md | Defense in Depth Strategy | 136-259 |

---

## Success Metrics

| Metric | v1.2.0 (Current) | v2.0.0 (Target) |
|---|---|---|
| Detection patterns | 190 | 220+ |
| Attack categories | 40+ | 45+ |
| Runtime guard modules | 0 | 5 |
| Apps consuming guards | 0 | 4+ (scraper-core, osint-auditor, broker-removal, vuln-scanner) |
| OpenClaw gap coverage | ~40% | ~90% |
| OWASP ASI coverage | Mapped | Mapped + runtime enforcement |
| Test count | ~123 | ~180+ |

---

## Build Order Summary

| # | Phase | Effort | Dependencies | Deliverable |
|---|---|---|---|---|
| 1 | New detection patterns | 1-2 sessions | None | 30+ patterns, 220+ total |
| 2 | SSRF Guard | 1 session | None | `src/guards/ssrf.ts` |
| 3 | Download Guard | Half session | None | `src/guards/download.ts` |
| 4 | Exec Allowlist | 1 session | None | `src/guards/exec-allow.ts` |
| 5 | Path Traversal Validator | 1 session | None | `src/guards/fs-safe.ts` |
| 6 | detect-secrets CI | Half session | None | `.secrets.baseline` + CI config |
| 7 | Cross-scan vuln-scanner rules | 1-2 sessions | Phase 1 (patterns) | New SAST rules in vuln-scanner |
| 8 | Webhook Verifier | Half session | None | `src/guards/webhook.ts` |
| 9 | Release v2.0.0 | Half session | Phases 1-5 minimum | npm publish + public repo sync |

**Total estimated effort:** 7-9 sessions

Phases 1-5 are independent of each other and can be built in any order. Phase 7 depends on Phase 1. Phase 9 depends on 1-5.

---

*This plan transforms agent-security from a static pattern scanner into a comprehensive runtime security library, directly informed by 80+ real-world vulnerability fixes from a production AI agent platform.*
