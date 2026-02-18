/**
 * Auth Anti-Pattern Tests
 *
 * Tests for authentication/authorization anti-patterns derived from
 * OpenClaw Category 4 (Auth/Access Control) and Category 8 (Timing Attacks).
 */

import { describe, it, expect } from 'vitest';
import { authAntiPatterns, timingAttackPatterns } from '../src/patterns/rce.js';
import { matchPatterns } from '../src/scanner/engine.js';

describe('Auth Anti-Patterns', () => {
  it('should detect fail-open catch block', () => {
    const code = `} catch (err) { return true; // fail open! }`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('auth_fail_open_catch');
  });

  it('should detect fail-open with "allow"', () => {
    const code = `catch (e) { allow(); }`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect string "undefined" comparison', () => {
    const code = `if (token === "undefined") { authenticate(); }`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('auth_string_undefined');
  });

  it('should detect reversed string "undefined" comparison', () => {
    const code = `if ("undefined" === token) { proceed(); }`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect partial identity match with startsWith', () => {
    const code = `if (allowlist.some(id => sender.startsWith(id)))`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    // The pattern targets userId/username/email/identity/sender/mxid/jid + startsWith/includes
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('auth_partial_identity_match');
  });

  it('should detect partial match with includes on username', () => {
    const code = `if (username.includes(query))`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag normal catch-and-deny', () => {
    const code = `catch (err) { return false; }`;
    const findings = matchPatterns(authAntiPatterns, code, 'auth.ts');
    expect(findings.length).toBe(0);
  });
});

describe('Timing Attack Patterns', () => {
  it('should detect non-constant-time secret comparison', () => {
    const code = `if (secret === expectedSecret) { grant(); }`;
    const findings = matchPatterns(timingAttackPatterns, code, 'webhook.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern.name).toBe('timing_unsafe_secret_compare');
  });

  it('should detect token comparison with ===', () => {
    const code = `if (token === storedToken) { authenticated = true; }`;
    const findings = matchPatterns(timingAttackPatterns, code, 'auth.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect HMAC comparison with ==', () => {
    const code = `if (hmac == expectedHmac) return true;`;
    const findings = matchPatterns(timingAttackPatterns, code, 'verify.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect signature comparison', () => {
    const code = `const valid = signature === computedSignature;`;
    const findings = matchPatterns(timingAttackPatterns, code, 'webhook.ts');
    expect(findings.length).toBeGreaterThan(0);
  });
});
