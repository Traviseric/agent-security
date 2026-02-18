# Agent Security Roadmap

Current: `@empowered-humanity/agent-security@1.2.0` → v2.0.0 | 220 patterns | 5 runtime guards | 254 tests | 45+ attack categories
Target: v2.0.0 npm publish + public repo sync

---

## What Exists Today

- Pattern-based security analysis via CLI and JSON output
- 190 detection patterns across 40+ attack categories
- Prompt injection, credential exposure, OWASP ASI, MCP attack detection
- GitHub Action integration (`action.yml`)
- Pre-commit hook support
- Published on npm

## v2.0 — Research-Driven Priorities

Source: OpenClaw vulnerability catalog (80+ commits, 12 categories), Gemini deep research (45 sources, 8 CVEs, ClawHavoc campaign), AI Agent Security Fundamentals + Best Practices.

Detailed plan: [`V2_IMPLEMENTATION_PLAN.md`](./V2_IMPLEMENTATION_PLAN.md)

**Key insight:** We lead on AI-layer detection (injection, CAPE, MCP, RAG). OpenClaw's infrastructure-layer hardening reveals gaps. Closing them turns agent-security from a static scanner into a runtime security library that the whole monorepo consumes.

### v2.0 Build Phases

| # | Phase | Effort | What Ships | Status |
|---|-------|--------|-----------|--------|
| 1 | New detection patterns (30) | 1-2 sessions | Infrastructure attacks, auth anti-patterns, supply chain, container misconfig | ✅ Complete |
| 2 | SSRF Guard module | 1 session | `src/guards/ssrf.ts` — DNS pinning, IP blocklists, redirect validation | ✅ Complete |
| 3 | Download Guard module | Half session | `src/guards/download.ts` — size caps, timeouts, content-type validation | ✅ Complete |
| 4 | Exec Allowlist module | 1 session | `src/guards/exec-allow.ts` — default-deny, resolved path matching, env filtering | ✅ Complete |
| 5 | Path Traversal Validator | 1 session | `src/guards/fs-safe.ts` — TOCTOU-safe root-bounded file access | ✅ Complete |
| 6 | detect-secrets in CI | Half session | `.secrets.baseline` + CI workflow for whole monorepo | Not Started |
| 7 | Cross-scan vuln-scanner rules | 1-2 sessions | SAST rules importing agent-security patterns | Not Started |
| 8 | Webhook Verifier | Half session | `src/guards/webhook.ts` — timing-safe HMAC for API webhooks | ✅ Complete |
| 9 | Release v2.0.0 | Half session | npm publish, public repo sync, SBOM, changelog | Ready (1-5, 8 done) |

### v2.0 Pattern Additions (Phase 1 Detail)

| Pattern Group | Count | Source | Target File |
|---|---|---|---|
| Env var injection (LD_PRELOAD, DYLD_*, PATH) | 4 | OpenClaw Cat 3 | `infrastructure.ts` (new) |
| Symlink traversal | 2 | OpenClaw Cat 1 | `infrastructure.ts` (new) |
| Windows exec evasion (cmd chain, encoded PS) | 3 | OpenClaw Cat 3 | `infrastructure.ts` (new) |
| Network/fetch misconfig (no timeout, no size limit) | 3 | OpenClaw Cat 6 | `infrastructure.ts` (new) |
| Extended SSRF (link-local, CGNAT, IPv6 mapped/loopback) | 4 | OpenClaw Cat 2 | `infrastructure.ts` (new) |
| Bind/proxy misconfig | 2 | OpenClaw Cat 4 | `infrastructure.ts` (new) |
| Auth anti-patterns (fail-open, string undefined, partial match, timing-unsafe) | 4 | OpenClaw Cat 4, 8 | `rce.ts`, `credentials.ts` |
| Supply chain install (curl\|sh, encoded PS, password ZIP, manual init) | 4 | ClawHavoc campaign | `defense-evasion.ts` |
| Container misconfig (home mount, host network, seccomp/apparmor unconfined) | 4 | Gemini anti-patterns | `defense-evasion.ts` |
| **Total** | **~30** | | |

### v2.0 Guard Modules (Phases 2-5, 8 Detail)

| Module | OpenClaw Reference | Monorepo Consumers |
|---|---|---|
| **SSRF Guard** — RFC 1918/loopback/link-local/CGNAT/IPv6 blocklist, DNS pinning, redirect re-validation | `src/infra/net/ssrf.ts` (131 lines) | scraper-core, osint-auditor, broker-removal, vuln-scanner |
| **Download Guard** — body size cap, connection+response timeouts, content-type check | Category 6 DoS fixes (4 vulns) | scraper-core, osint-auditor, broker-removal |
| **Exec Allowlist** — default-deny, resolved binary path matching, env var filtering, platform-specific evasion | `src/infra/exec-approvals.ts` (540+ lines) | pentest-toolkit, any app with child_process |
| **Path Traversal Validator** — root-bounded access, symlink detection, TOCTOU prevention | `src/infra/fs-safe.ts` (103 lines) | any app reading user-specified paths |
| **Webhook Verifier** — crypto.timingSafeEqual wrapper, multi-provider (GitHub, Slack, Stripe) | `extensions/voice-call/src/webhook-security.ts` | osint-auditor REST API |

### v2.0 Success Metrics

| Metric | v1.2.0 | v2.0.0 Target |
|---|---|---|
| Detection patterns | 190 | **220** ✅ |
| Attack categories | 40+ | **45+** ✅ |
| Runtime guard modules | 0 | **5** ✅ |
| Apps consuming guards | 0 | 4+ (pending integration) |
| OpenClaw gap coverage | ~40% | **~90%** ✅ |
| Test count | ~123 | **254** ✅ |

---

## Proposal-Driven Priorities

Source: FA830726RB019 (AFLCMC SBOM Vulnerability Scanning RFI)

Agent Security's pattern engine is the foundation for policy enforcement. The SOW asks for configurable policy rules, Dockerfile analysis, and compliance checking — all extensions of what the pattern matcher already does.

### P0 — Required for Contract Competitiveness

| # | SOW Requirement | Feature | Status |
|---|----------------|---------|--------|
| 18 | Policy engine for Dockerfile instructions (warn/stop) | Dockerfile policy enforcement | **Adjacent** — extends pattern engine |
| 19 | Dockerfile linting for best practices | Dockerfile linting | **Adjacent** — extends pattern engine |
| 21 | Compliance checking against DISA STIG and CIS | STIG/CIS compliance rules | **New** |
| 23 | User-defined custom policies | Custom policy creation | **New** |
| 24 | Config-as-code policies importable via CLI and API | Config-as-code policy engine | **New** |
| 32 | Define security policies (e.g., fail builds on critical vulns) | Build-breaking policy enforcement | **Adjacent** — extends CI/CD integration |

### P1 — Differentiators

| # | SOW Requirement | Feature | Status |
|---|----------------|---------|--------|
| 17 | Malware scanning | Malware pattern detection | **Adjacent** — extends pattern library |
| 20 | File metadata retrieval and policy evaluation | File metadata analysis | **New** |
| 22 | Examine file content and evaluate policy rules | File content policy evaluation | **New** |
| 35 | Secure development lifecycle (SAST/DAST) | Self-scanning capability | **Process** — organizational |

### Build Order

1. Dockerfile linting rules (lowest effort, direct extension of pattern engine)
2. Dockerfile policy enforcement (warn/stop/fail modes)
3. Config-as-code policy format (YAML/JSON policy definitions)
4. Custom policy CLI import (`agent-security policy import policy.yaml`)
5. DISA STIG compliance rules (container-focused STIGs first)
6. CIS Benchmark compliance rules
7. Build-breaking enforcement for CI/CD pipelines
8. File metadata analysis (permissions, hashes, ownership)
9. File content policy evaluation
10. Malware scanning pattern extensions

## Deployment Compliance

Agent Security is currently an npm package with no container. To deploy in DoD environments, it needs containerization for use as a pipeline service (not just a CLI tool).

### Containerization (not started)

- [ ] Dockerfile — multi-stage, Alpine-based, non-root execution
- [ ] .dockerignore
- [ ] Docker Compose for local development
- [ ] API server mode (HTTP endpoint wrapping CLI analysis)
- [ ] Docker Compose production override with resource limits

### Kubernetes / Big Bang (not started)

- [ ] Helm chart (Chart.yaml, values.yaml, templates/)
- [ ] Deployment manifest with resource limits and health checks
- [ ] Service manifest
- [ ] Istio VirtualService for service mesh integration
- [ ] NetworkPolicy restricting ingress/egress
- [ ] Non-root securityContext (runAsNonRoot, readOnlyRootFilesystem)
- [ ] IronBank-compatible base image reference
- [ ] ConfigMap for default policy configuration
- [ ] Volume mount for custom policy files

### Compliance Specs

| Requirement | Spec | Current Status |
|-------------|------|----------------|
| Base image | IronBank registry or Alpine hardened | No container yet |
| User | Non-root (UID 1000+) | No container yet |
| Filesystem | Read-only root, tmpfs for /tmp | No container yet |
| Network | Istio sidecar, mTLS | No container yet |
| Network policy | Deny-all default, explicit allow | No container yet |
| Health checks | Liveness + readiness probes | No container yet |
| Resource limits | CPU and memory limits set | No container yet |
| Logging | Structured JSON to stdout | CLI outputs JSON — needs structured logging |
| Policy storage | ConfigMap + PVC for custom policies | No container yet |

### Note on Deployment Model

Agent Security can serve two roles in a DoD pipeline:

1. **CI/CD tool** — runs as a GitHub Action or pipeline step (current model, no container needed)
2. **Pipeline service** — runs as a persistent API that other services call for policy checks (needs containerization)

Both models should be supported. The Helm chart should include a Job template for CI/CD mode and a Deployment template for service mode.

---

## Engineering Principles Compliance

Agent Security is the simplest product from an engineering principles standpoint — a CLI tool with no external dependencies. The engineering principles (container standards, resilience patterns, observability, API design, secret management, CI/CD) apply primarily when the API server mode is built for pipeline service deployment. Until then, the CLI tool inherits compliance through its GitHub Action integration and structured JSON output.

### Infrastructure Prerequisites (Before Service Mode)

| Task | Engineering Principle | Priority | Status |
|------|----------------------|----------|--------|
| API server mode (HTTP endpoint wrapping scan/patterns/stats functionality) | API Design | P0 | Not Started |
| Dockerfile (multi-stage, Alpine, non-root, read-only filesystem, health check) | Container Standards | P0 | Not Started |
| Docker Compose (dev + prod with resource limits) | Container Standards | P1 | Not Started |
| Dual-mode Helm chart (Job template for CI/CD + Deployment template for service) | Kubernetes / Deployment Standards | P1 | Not Started |
| Own SBOM (CycloneDX SBOM generated per release) | CI/CD — Supply Chain Security | P0 | Not Started |

### Service Mode Engineering Tasks

| Task | Engineering Principle | Priority | Status |
|------|----------------------|----------|--------|
| Fail-fast config validation (validate env vars, policy config paths on startup) | Resilience and Error Handling | P0 | Not Started |
| Default timeouts (30s for scan operations on large codebases) | Resilience and Error Handling | P0 | Not Started |
| Structured JSON logging to stdout (extend existing JSON output) | Minimum Viable Observability | P0 | Not Started |
| Health check endpoint (liveness + readiness probes) | Minimum Viable Observability | P0 | Not Started |
| X-Request-ID acceptance and propagation | Minimum Viable Observability | P1 | Not Started |
| RED metrics (rate, errors, duration per scan type) | Minimum Viable Observability | P1 | Not Started |
| Secret scanning in CI (TruffleHog/Gitleaks on every push) | Secret Management | P0 | Not Started |
| Rate limiting on API endpoints | API Design | P1 | Not Started |

### Per-Feature Engineering Checklist

- [ ] New detection pattern? Add to test suite, verify no false positive regression
- [ ] New API endpoint? Add to OpenAPI spec, rate limiting, consistent error format
- [ ] New policy format (YAML/JSON)? Validate on load, fail-fast on invalid schema
- [ ] New output format (SARIF, HTML)? Follow reporting standards from engineering principles
- [ ] Container image updated? Regenerate own SBOM

---

## How This Roadmap Gets Updated

When new solicitations are assessed (via `PRODUCT_ROADMAP_MAPPING.md` in the proposals system), a Claude Code agent reviews the mapping and updates this file with new requirements, adjusted priorities, and compliance specs. Features that multiple solicitations request move up in priority.

Last updated: 2026-02-17 — v2.0 Phases 1-5, 8 complete (220 patterns, 5 guards, 254 tests)
