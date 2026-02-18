/**
 * SSRF Guard Tests
 */

import { describe, it, expect } from 'vitest';
import { createSsrfGuard, isPrivateIp, isPrivateIpv4, isPrivateIpv6 } from '../src/guards/ssrf.js';

describe('isPrivateIpv4', () => {
  it('should detect loopback', () => {
    expect(isPrivateIpv4('127.0.0.1')).toBe(true);
    expect(isPrivateIpv4('127.255.255.255')).toBe(true);
  });

  it('should detect RFC 1918 Class A', () => {
    expect(isPrivateIpv4('10.0.0.1')).toBe(true);
    expect(isPrivateIpv4('10.255.255.255')).toBe(true);
  });

  it('should detect RFC 1918 Class B', () => {
    expect(isPrivateIpv4('172.16.0.1')).toBe(true);
    expect(isPrivateIpv4('172.31.255.255')).toBe(true);
  });

  it('should detect RFC 1918 Class C', () => {
    expect(isPrivateIpv4('192.168.0.1')).toBe(true);
    expect(isPrivateIpv4('192.168.255.255')).toBe(true);
  });

  it('should detect link-local', () => {
    expect(isPrivateIpv4('169.254.1.1')).toBe(true);
    expect(isPrivateIpv4('169.254.169.254')).toBe(true);
  });

  it('should detect CGNAT', () => {
    expect(isPrivateIpv4('100.64.0.1')).toBe(true);
    expect(isPrivateIpv4('100.127.255.255')).toBe(true);
  });

  it('should allow public IPs', () => {
    expect(isPrivateIpv4('8.8.8.8')).toBe(false);
    expect(isPrivateIpv4('1.1.1.1')).toBe(false);
    expect(isPrivateIpv4('93.184.216.34')).toBe(false);
  });
});

describe('isPrivateIpv6', () => {
  it('should detect loopback', () => {
    expect(isPrivateIpv6('::1')).toBe(true);
  });

  it('should detect unspecified', () => {
    expect(isPrivateIpv6('::')).toBe(true);
  });

  it('should detect ULA', () => {
    expect(isPrivateIpv6('fc00::1')).toBe(true);
    expect(isPrivateIpv6('fd12:3456::1')).toBe(true);
  });

  it('should detect link-local', () => {
    expect(isPrivateIpv6('fe80::1')).toBe(true);
  });

  it('should detect IPv4-mapped with private IP', () => {
    expect(isPrivateIpv6('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIpv6('::ffff:10.0.0.1')).toBe(true);
    expect(isPrivateIpv6('::ffff:192.168.1.1')).toBe(true);
  });

  it('should allow IPv4-mapped with public IP', () => {
    expect(isPrivateIpv6('::ffff:8.8.8.8')).toBe(false);
  });
});

describe('isPrivateIp', () => {
  it('should handle IPv4', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('should handle IPv6', () => {
    expect(isPrivateIp('::1')).toBe(true);
  });
});

describe('createSsrfGuard', () => {
  it('should block private IPs by default', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('http://127.0.0.1/admin');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Private IP');
  });

  it('should block localhost hostname', async () => {
    const guard = createSsrfGuard({ pinDns: false });
    const result = await guard.validateUrl('http://localhost/admin');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked hostname');
  });

  it('should block .local domains', async () => {
    const guard = createSsrfGuard({ pinDns: false });
    const result = await guard.validateUrl('http://printer.local/api');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked hostname');
  });

  it('should block .internal domains', async () => {
    const guard = createSsrfGuard({ pinDns: false });
    const result = await guard.validateUrl('http://metadata.google.internal/computeMetadata');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked hostname');
  });

  it('should block non-http protocols', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('file:///etc/passwd');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked protocol');
  });

  it('should block ftp protocol', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('ftp://evil.com/file');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked protocol');
  });

  it('should reject invalid URLs', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('not-a-url');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Invalid URL');
  });

  it('should enforce hostname allowlist', async () => {
    const guard = createSsrfGuard({
      allowedHostnames: ['api.github.com'],
      pinDns: false,
    });

    const blocked = await guard.validateUrl('http://evil.com/api');
    expect(blocked.safe).toBe(false);
    expect(blocked.reason).toContain('not in allowlist');
  });

  it('should allow private IPs when policy permits', async () => {
    const guard = createSsrfGuard({ allowPrivateNetwork: true });
    const result = await guard.validateUrl('http://192.168.1.1/admin');
    expect(result.safe).toBe(true);
  });

  it('should block cloud metadata IP', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('http://169.254.169.254/latest/meta-data/');
    expect(result.safe).toBe(false);
  });

  it('should block IPv6 loopback', async () => {
    const guard = createSsrfGuard();
    const result = await guard.validateUrl('http://[::1]:8080/admin');
    expect(result.safe).toBe(false);
  });

  it('should block extra blocked hostnames', async () => {
    const guard = createSsrfGuard({
      blockedHostnames: ['evil.com'],
      pinDns: false,
    });
    const result = await guard.validateUrl('http://evil.com/api');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Blocked hostname');
  });
});
