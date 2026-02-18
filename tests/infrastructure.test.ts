/**
 * Infrastructure Attack Pattern Tests
 *
 * Tests for OpenClaw-derived infrastructure-layer patterns:
 * env injection, symlink traversal, Windows exec evasion,
 * fetch misconfig, extended SSRF, bind/proxy misconfig.
 */

import { describe, it, expect } from 'vitest';
import {
  envInjectionPatterns,
  symlinkTraversalPatterns,
  windowsExecEvasionPatterns,
  fetchMisconfigPatterns,
  extendedSsrfPatterns,
  bindProxyMisconfigPatterns,
  allInfrastructurePatterns,
} from '../src/patterns/infrastructure.js';
import { matchPatterns } from '../src/scanner/engine.js';

describe('Infrastructure Patterns — Total Count', () => {
  it('should have 18+ infrastructure patterns', () => {
    expect(allInfrastructurePatterns.length).toBeGreaterThanOrEqual(18);
  });
});

// ═══════════════════════════════════════
// Env Injection
// ═══════════════════════════════════════

describe('Env Injection Patterns', () => {
  it('should detect LD_PRELOAD injection', () => {
    const findings = matchPatterns(envInjectionPatterns, 'LD_PRELOAD=/tmp/evil.so ./app', 'run.sh');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('env_ld_preload');
  });

  it('should detect DYLD_INSERT_LIBRARIES', () => {
    const findings = matchPatterns(envInjectionPatterns, 'DYLD_INSERT_LIBRARIES=/tmp/evil.dylib ./app', 'run.sh');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('env_dyld_inject');
  });

  it('should detect DYLD_FRAMEWORK_PATH', () => {
    const findings = matchPatterns(envInjectionPatterns, 'DYLD_FRAMEWORK_PATH=/tmp/evil ./app', 'run.sh');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect LD_LIBRARY_PATH override', () => {
    const findings = matchPatterns(envInjectionPatterns, 'LD_LIBRARY_PATH=/tmp/evil ./app', 'run.sh');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('env_ld_library_path');
  });

  it('should detect PATH override to /tmp', () => {
    const findings = matchPatterns(envInjectionPatterns, 'PATH=/tmp/bin:$PATH ./app', 'run.sh');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('env_path_override');
  });

  it('should not match normal env usage', () => {
    const findings = matchPatterns(envInjectionPatterns, 'const dbUrl = process.env.DATABASE_URL;', 'app.ts');
    expect(findings.length).toBe(0);
  });
});

// ═══════════════════════════════════════
// Symlink Traversal
// ═══════════════════════════════════════

describe('Symlink Traversal Patterns', () => {
  it('should detect symlink with path traversal', () => {
    const findings = matchPatterns(symlinkTraversalPatterns, 'ln -s ../../etc/passwd ./link', 'exploit.sh');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('symlink_create_outside');
  });

  it('should detect ln -sf with traversal', () => {
    const findings = matchPatterns(symlinkTraversalPatterns, 'ln -sf ../../../root/.ssh/id_rsa ./key', 'exploit.sh');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect file read with user-controlled path', () => {
    const findings = matchPatterns(symlinkTraversalPatterns, 'fs.readFile(userPath, "utf8", cb)', 'server.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('symlink_no_lstat');
  });
});

// ═══════════════════════════════════════
// Windows Exec Evasion
// ═══════════════════════════════════════

describe('Windows Exec Evasion Patterns', () => {
  it('should detect cmd.exe command chaining with &', () => {
    const findings = matchPatterns(windowsExecEvasionPatterns, 'cmd.exe /c "safe.exe & evil.exe"', 'exploit.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('win_cmd_chain');
  });

  it('should detect PowerShell -EncodedCommand', () => {
    const findings = matchPatterns(windowsExecEvasionPatterns, 'powershell -EncodedCommand JABzAD0ATgBlAHc...', 'exploit.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('win_powershell_encoded');
  });

  it('should detect PowerShell -ec shorthand', () => {
    const findings = matchPatterns(windowsExecEvasionPatterns, 'powershell.exe -ec JABzAD0ATg==', 'exploit.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect cmd.exe pipe chaining', () => {
    const findings = matchPatterns(windowsExecEvasionPatterns, 'cmd /c "dir | evil.exe"', 'exploit.ts');
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════
// Extended SSRF
// ═══════════════════════════════════════

describe('Extended SSRF Patterns', () => {
  it('should detect link-local SSRF (169.254.x.x)', () => {
    const findings = matchPatterns(extendedSsrfPatterns, 'fetch("http://169.254.1.1/admin")', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('ssrf_link_local');
  });

  it('should detect CGNAT SSRF (100.64.x.x)', () => {
    const findings = matchPatterns(extendedSsrfPatterns, 'fetch("http://100.100.1.1/api")', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('ssrf_cgnat');
  });

  it('should detect IPv6-mapped IPv4 SSRF', () => {
    const findings = matchPatterns(extendedSsrfPatterns, 'fetch("http://[::ffff:127.0.0.1]/admin")', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('ssrf_ipv6_mapped_v4');
  });

  it('should detect IPv6 loopback SSRF', () => {
    const findings = matchPatterns(extendedSsrfPatterns, 'fetch("http://[::1]:8080/admin")', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('ssrf_ipv6_loopback');
  });

  it('should not match public IPs', () => {
    const findings = matchPatterns(extendedSsrfPatterns, 'fetch("http://8.8.8.8/dns")', 'app.ts');
    expect(findings.length).toBe(0);
  });
});

// ═══════════════════════════════════════
// Bind/Proxy Misconfig
// ═══════════════════════════════════════

describe('Bind/Proxy Misconfiguration Patterns', () => {
  it('should detect 0.0.0.0 binding', () => {
    const findings = matchPatterns(bindProxyMisconfigPatterns, 'server.listen(8080, "0.0.0.0")', 'server.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('bind_all_interfaces');
  });

  it('should detect :: IPv6 all-interfaces binding', () => {
    const findings = matchPatterns(bindProxyMisconfigPatterns, 'host: "::"', 'config.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect X-Forwarded-For usage', () => {
    const findings = matchPatterns(bindProxyMisconfigPatterns, 'const ip = req.headers["x-forwarded-for"]', 'middleware.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('forwarded_header_unvalidated');
  });

  it('should not match localhost binding', () => {
    const findings = matchPatterns(bindProxyMisconfigPatterns, 'server.listen(8080, "127.0.0.1")', 'server.ts');
    expect(findings.length).toBe(0);
  });
});

// ═══════════════════════════════════════
// Fetch Misconfig
// ═══════════════════════════════════════

describe('Fetch Misconfiguration Patterns', () => {
  it('should detect fetch without timeout', () => {
    const findings = matchPatterns(fetchMisconfigPatterns, 'fetch(url).then(r => r.json());', 'api.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect response body consumed without size limit', () => {
    const findings = matchPatterns(fetchMisconfigPatterns, 'const data = await response.arrayBuffer()', 'download.ts');
    expect(findings.length).toBeGreaterThan(0);
  });
});
