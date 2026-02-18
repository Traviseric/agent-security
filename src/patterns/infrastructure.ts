/**
 * Infrastructure Attack Patterns
 *
 * Patterns for detecting infrastructure-layer vulnerabilities identified
 * from OpenClaw's 80+ security commits across 12 vulnerability categories.
 *
 * Categories covered:
 * - Environment variable injection (LD_PRELOAD, DYLD_*, PATH override)
 * - Symlink traversal bypasses
 * - Windows-specific exec evasion (cmd.exe chains, encoded PowerShell)
 * - Network/fetch misconfigurations (missing timeouts, missing size limits)
 * - Extended SSRF vectors (link-local, CGNAT, IPv6 mapped/loopback)
 * - Bind/proxy misconfigurations (0.0.0.0 binding, unvalidated forwarded headers)
 *
 * Sources: OPENCLAW-CAT1 through OPENCLAW-CAT6
 */

import type { DetectionPattern } from './types.js';

// ═══════════════════════════════════════════════════════════
// Environment Variable Injection
// Source: OpenClaw Category 3 — Exec / Sandbox Escape (#4)
// ═══════════════════════════════════════════════════════════

export const envInjectionPatterns: DetectionPattern[] = [
  {
    name: 'env_ld_preload',
    pattern: /LD_PRELOAD\s*=/i,
    severity: 'critical',
    category: 'env_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'LD_PRELOAD injection — loads arbitrary shared library before all others',
    example: 'LD_PRELOAD=/tmp/evil.so ./target',
    remediation: 'Strip LD_PRELOAD from environment before exec. Never pass through from user input.',
  },
  {
    name: 'env_dyld_inject',
    pattern: /DYLD_(?:INSERT_LIBRARIES|FRAMEWORK_PATH|LIBRARY_PATH|FALLBACK_LIBRARY_PATH)\s*=/i,
    severity: 'critical',
    category: 'env_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'macOS DYLD injection — loads arbitrary dylib into process',
    example: 'DYLD_INSERT_LIBRARIES=/tmp/evil.dylib ./target',
    remediation: 'Strip all DYLD_* variables from environment before exec.',
  },
  {
    name: 'env_ld_library_path',
    pattern: /LD_LIBRARY_PATH\s*=/i,
    severity: 'high',
    category: 'env_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'LD_LIBRARY_PATH override — can redirect shared library resolution',
    example: 'LD_LIBRARY_PATH=/tmp/evil ./target',
    remediation: 'Strip LD_LIBRARY_PATH from environment or validate against allowlist.',
  },
  {
    name: 'env_path_override',
    pattern: /\bPATH\s*=\s*(?:["']?\/?tmp|["']?\/dev|["']?\.)/i,
    severity: 'high',
    category: 'env_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'PATH override pointing to tmp/relative dir — can substitute binaries',
    example: 'PATH=/tmp/evil:$PATH ./target',
    remediation: 'Never allow user-controlled PATH overrides. Use absolute paths for exec.',
  },
];

// ═══════════════════════════════════════════════════════════
// Symlink Traversal
// Source: OpenClaw Category 1 — Path Traversal / LFI (#6)
// ═══════════════════════════════════════════════════════════

export const symlinkTraversalPatterns: DetectionPattern[] = [
  {
    name: 'symlink_create_outside',
    pattern: /ln\s+-s[f]?\s+.*\.\.\//i,
    severity: 'high',
    category: 'path_traversal',
    source: 'OPENCLAW-CAT1',
    context: 'code',
    description: 'Symlink creation with path traversal — can point outside sandbox',
    example: 'ln -s ../../etc/passwd ./link',
    remediation: 'Block symlink creation that targets outside the sandbox root. Use lstat() before open().',
  },
  {
    name: 'symlink_no_lstat',
    pattern: /(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream|open\()\s*\([^)]*(?:userPath|filePath|inputPath|req\.|params\.|query\.)/i,
    severity: 'medium',
    category: 'path_traversal',
    source: 'OPENCLAW-CAT1',
    context: 'code',
    description: 'File read with user-controlled path — missing lstat/symlink check',
    example: 'fs.readFile(userPath, callback)',
    remediation: 'Use lstat() to check for symlinks before opening. Use O_NOFOLLOW on Unix.',
  },
];

// ═══════════════════════════════════════════════════════════
// Windows Exec Evasion
// Source: OpenClaw Category 3 — Exec / Sandbox Escape (#7)
// ═══════════════════════════════════════════════════════════

export const windowsExecEvasionPatterns: DetectionPattern[] = [
  {
    name: 'win_cmd_chain',
    pattern: /cmd(?:\.exe)?\s+\/[ck]\s+["'][^"']*[&|][^"']*["']/i,
    severity: 'critical',
    category: 'code_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'Windows cmd.exe command chaining via & or | — can append arbitrary commands',
    example: 'cmd.exe /c "safe.exe & evil.exe"',
    remediation: 'Never pass user input to cmd.exe /c. Use direct binary execution without shell.',
  },
  {
    name: 'win_powershell_encoded',
    pattern: /powershell(?:\.exe)?\s+.*-(?:EncodedCommand|ec|e)\s+/i,
    severity: 'critical',
    category: 'code_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'PowerShell -EncodedCommand — executes base64-encoded commands, evades inspection',
    example: 'powershell -EncodedCommand JABzAD0...',
    remediation: 'Block -EncodedCommand/-ec/-e flags. Require plaintext commands for auditability.',
  },
  {
    name: 'win_cmd_pipe_chain',
    pattern: /cmd(?:\.exe)?\s+\/[ck]\s+.*\|\s*\w/i,
    severity: 'high',
    category: 'code_injection',
    source: 'OPENCLAW-CAT3',
    context: 'code',
    description: 'Windows cmd.exe pipe chaining — can redirect output to malicious command',
    example: 'cmd /c "dir | evil.exe"',
    remediation: 'Avoid cmd.exe for command execution. Use direct binary invocation.',
  },
];

// ═══════════════════════════════════════════════════════════
// Network / Fetch Misconfiguration
// Source: OpenClaw Category 6 — Denial of Service (CWE-400)
// ═══════════════════════════════════════════════════════════

export const fetchMisconfigPatterns: DetectionPattern[] = [
  {
    name: 'fetch_no_timeout',
    pattern: /(?:fetch|axios\.(?:get|post|put|delete|request)|got(?:\.(?:get|post))?|request|urllib|requests\.(?:get|post))\s*\([^)]*\)\s*(?:\.then|;|\n)/i,
    severity: 'medium',
    category: 'config_vulnerability',
    source: 'OPENCLAW-CAT6',
    context: 'code',
    description: 'External fetch without explicit timeout — vulnerable to slowloris/hang',
    example: 'fetch(url).then(r => r.json())',
    remediation: 'Always set timeout: { connection: 10000, response: 30000 } on external fetches.',
  },
  {
    name: 'fetch_no_size_limit',
    pattern: /(?:arrayBuffer|blob|text|json|buffer|body)\s*\(\s*\)/i,
    severity: 'medium',
    category: 'config_vulnerability',
    source: 'OPENCLAW-CAT6',
    context: 'code',
    description: 'Response body consumed without size limit — vulnerable to memory exhaustion',
    example: 'const data = await response.arrayBuffer()',
    remediation: 'Stream response body with size cap. Abort if Content-Length exceeds limit.',
  },
  {
    name: 'download_no_content_length_check',
    pattern: /(?:pipe|pipeTo|pipeThrough)\s*\(/i,
    severity: 'low',
    category: 'config_vulnerability',
    source: 'OPENCLAW-CAT6',
    context: 'code',
    description: 'Stream pipe without size validation — check Content-Length before piping',
    example: 'response.body.pipe(writeStream)',
    remediation: 'Check Content-Length header and enforce max body size before piping.',
  },
];

// ═══════════════════════════════════════════════════════════
// Extended SSRF Vectors
// Source: OpenClaw Category 2 — SSRF (5 vulns)
// These extend the existing SSRF patterns in rce.ts with
// additional IP ranges and IPv6 vectors.
// ═══════════════════════════════════════════════════════════

export const extendedSsrfPatterns: DetectionPattern[] = [
  {
    name: 'ssrf_link_local',
    pattern: /https?:\/\/169\.254\.\d{1,3}\.\d{1,3}/i,
    severity: 'critical',
    category: 'ssrf',
    source: 'OPENCLAW-CAT2',
    description: 'SSRF to link-local address (169.254.x.x) — cloud metadata, APIPA',
    example: 'http://169.254.1.1/admin',
    remediation: 'Block all 169.254.0.0/16 in outbound request validation.',
  },
  {
    name: 'ssrf_cgnat',
    pattern: /https?:\/\/100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d{1,3}\.\d{1,3}/i,
    severity: 'high',
    category: 'ssrf',
    source: 'OPENCLAW-CAT2',
    description: 'SSRF to CGNAT address (100.64.0.0/10) — carrier-grade NAT, Tailscale',
    example: 'http://100.100.1.1/api',
    remediation: 'Block 100.64.0.0/10 in outbound request validation.',
  },
  {
    name: 'ssrf_ipv6_mapped_v4',
    pattern: /https?:\/\/\[?::ffff:(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i,
    severity: 'critical',
    category: 'ssrf',
    source: 'OPENCLAW-CAT2',
    description: 'SSRF via IPv6-mapped IPv4 address — bypasses IPv4-only blocklists',
    example: 'http://[::ffff:127.0.0.1]/admin',
    remediation: 'Normalize IPv6-mapped addresses to IPv4 before blocklist check.',
  },
  {
    name: 'ssrf_ipv6_loopback',
    pattern: /https?:\/\/\[::1\]/i,
    severity: 'critical',
    category: 'ssrf',
    source: 'OPENCLAW-CAT2',
    description: 'SSRF to IPv6 loopback (::1) — bypasses IPv4 localhost checks',
    example: 'http://[::1]:8080/admin',
    remediation: 'Block ::1 alongside 127.0.0.0/8 in SSRF protection.',
  },
];

// ═══════════════════════════════════════════════════════════
// Bind / Proxy Misconfiguration
// Source: OpenClaw Category 4 — Auth / Access Control (#1, #2)
// ═══════════════════════════════════════════════════════════

export const bindProxyMisconfigPatterns: DetectionPattern[] = [
  {
    name: 'bind_all_interfaces',
    pattern: /(?:listen|bind|host)\s*[\(:=].*["'](?:0\.0\.0\.0|::)["']/i,
    severity: 'high',
    category: 'config_vulnerability',
    source: 'OPENCLAW-CAT4',
    context: 'code',
    description: 'Service binding to all interfaces — exposes to external network',
    example: 'server.listen(8080, "0.0.0.0")',
    remediation: 'Bind to 127.0.0.1 or ::1 for local-only services. Use reverse proxy for external access.',
  },
  {
    name: 'forwarded_header_unvalidated',
    pattern: /(?:x-forwarded-for|x-real-ip|x-forwarded-host|x-forwarded-proto)\b/i,
    severity: 'medium',
    category: 'config_vulnerability',
    source: 'OPENCLAW-CAT4',
    context: 'code',
    description: 'Forwarded header usage — must validate against trusted proxy list',
    example: 'const clientIp = req.headers["x-forwarded-for"]',
    remediation: 'Only trust X-Forwarded-* headers from explicitly configured trusted proxies. Fail closed if proxy config missing.',
  },
];

// ═══════════════════════════════════════════════════════════
// Combined Export
// ═══════════════════════════════════════════════════════════

export const allInfrastructurePatterns: DetectionPattern[] = [
  ...envInjectionPatterns,
  ...symlinkTraversalPatterns,
  ...windowsExecEvasionPatterns,
  ...fetchMisconfigPatterns,
  ...extendedSsrfPatterns,
  ...bindProxyMisconfigPatterns,
];
