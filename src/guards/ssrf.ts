/**
 * SSRF Guard Module
 *
 * Runtime SSRF protection with DNS pinning, IP blocklists, and
 * hostname validation. Prevents Server-Side Request Forgery by
 * validating URLs before fetching.
 *
 * Reference: OpenClaw src/infra/net/ssrf.ts (131 lines)
 * Source: OPENCLAW_SECURITY_ANALYSIS.md, Category 2 (5 vulns)
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { URL } from 'node:url';

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export interface SsrfPolicy {
  /** Allow requests to private/internal networks. Default: false */
  allowPrivateNetwork?: boolean;
  /** Explicit hostname allowlist. If set, only these hosts are permitted. */
  allowedHostnames?: string[];
  /** Additional hostnames to block beyond built-in defaults. */
  blockedHostnames?: string[];
  /** Follow redirects and re-validate each hop. Default: true */
  followRedirects?: boolean;
  /** Maximum redirect hops. Default: 5 */
  maxRedirects?: number;
  /** Pin DNS resolution to prevent rebinding attacks. Default: true */
  pinDns?: boolean;
}

export interface SsrfResult {
  safe: boolean;
  reason?: string;
  resolvedIp?: string;
  hostname?: string;
}

export interface SsrfGuard {
  validateUrl(url: string): Promise<SsrfResult>;
}

// ═══════════════════════════════════════════════════════════
// IP Range Checks
// ═══════════════════════════════════════════════════════════

/**
 * Parse an IPv4 address into a 32-bit number.
 */
function ipv4ToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Check if an IPv4 address is within a CIDR range.
 */
function ipv4InCidr(ip: string, cidr: string): boolean {
  const [rangeIp, bits] = cidr.split('/');
  const mask = (~0 << (32 - Number(bits))) >>> 0;
  return (ipv4ToNum(ip) & mask) === (ipv4ToNum(rangeIp) & mask);
}

/** Private/reserved IPv4 CIDR ranges */
const BLOCKED_IPV4_CIDRS = [
  '10.0.0.0/8',        // RFC 1918 Class A
  '172.16.0.0/12',     // RFC 1918 Class B
  '192.168.0.0/16',    // RFC 1918 Class C
  '127.0.0.0/8',       // Loopback
  '169.254.0.0/16',    // Link-local (APIPA, cloud metadata)
  '100.64.0.0/10',     // CGNAT (Tailscale, carrier NAT)
  '0.0.0.0/8',         // "This" network
  '224.0.0.0/4',       // Multicast
  '240.0.0.0/4',       // Reserved
  '192.0.0.0/24',      // IETF protocol assignments
  '192.0.2.0/24',      // TEST-NET-1
  '198.51.100.0/24',   // TEST-NET-2
  '203.0.113.0/24',    // TEST-NET-3
  '198.18.0.0/15',     // Benchmark testing
];

/**
 * Check if an IPv4 address is private/reserved.
 */
export function isPrivateIpv4(ip: string): boolean {
  return BLOCKED_IPV4_CIDRS.some(cidr => ipv4InCidr(ip, cidr));
}

/**
 * Check if an IPv6 address is private/reserved.
 * Handles: ::1 (loopback), fc00::/7 (ULA), fe80::/10 (link-local),
 * ::ffff:x.x.x.x (IPv4-mapped), :: (unspecified)
 */
export function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase().replace(/^\[|\]$/g, '');

  // Loopback
  if (normalized === '::1') return true;

  // Unspecified
  if (normalized === '::') return true;

  // IPv4-mapped IPv6 (::ffff:x.x.x.x)
  const v4MappedMatch = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4MappedMatch) {
    return isPrivateIpv4(v4MappedMatch[1]);
  }

  // Unique Local Address (fc00::/7)
  if (/^f[cd]/.test(normalized)) return true;

  // Link-local (fe80::/10)
  if (/^fe[89ab]/.test(normalized)) return true;

  return false;
}

/**
 * Check if any IP address (v4 or v6) is private/reserved.
 */
export function isPrivateIp(ip: string): boolean {
  if (isIP(ip) === 4) return isPrivateIpv4(ip);
  if (isIP(ip) === 6) return isPrivateIpv6(ip);

  // Try stripping brackets for IPv6
  const stripped = ip.replace(/^\[|\]$/g, '');
  if (isIP(stripped) === 6) return isPrivateIpv6(stripped);

  return false;
}

// ═══════════════════════════════════════════════════════════
// Hostname Checks
// ═══════════════════════════════════════════════════════════

const DEFAULT_BLOCKED_HOSTNAMES = [
  'localhost',
  'metadata.google.internal',
  'metadata.google.com',
];

const BLOCKED_HOSTNAME_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
];

function isBlockedHostname(hostname: string, extraBlocked: string[] = []): boolean {
  const lower = hostname.toLowerCase();

  if (DEFAULT_BLOCKED_HOSTNAMES.includes(lower)) return true;
  if (extraBlocked.some(h => h.toLowerCase() === lower)) return true;
  if (BLOCKED_HOSTNAME_SUFFIXES.some(suffix => lower.endsWith(suffix))) return true;

  return false;
}

// ═══════════════════════════════════════════════════════════
// URL Validation
// ═══════════════════════════════════════════════════════════

function parseUrl(urlStr: string): URL | null {
  try {
    return new URL(urlStr);
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════
// DNS Resolution with Pinning
// ═══════════════════════════════════════════════════════════

async function resolveHost(hostname: string): Promise<string[]> {
  // If it's already an IP, return directly
  if (isIP(hostname)) return [hostname];

  try {
    const result = await lookup(hostname, { all: true });
    return result.map(r => r.address);
  } catch {
    return [];
  }
}

// ═══════════════════════════════════════════════════════════
// Guard Factory
// ═══════════════════════════════════════════════════════════

/**
 * Create an SSRF guard with the given policy.
 *
 * @example
 * ```typescript
 * const guard = createSsrfGuard({ allowedHostnames: ['api.github.com'] });
 * const result = await guard.validateUrl(userProvidedUrl);
 * if (!result.safe) throw new Error(`SSRF blocked: ${result.reason}`);
 * ```
 */
export function createSsrfGuard(policy: SsrfPolicy = {}): SsrfGuard {
  const {
    allowPrivateNetwork = false,
    allowedHostnames,
    blockedHostnames = [],
    pinDns = true,
  } = policy;

  return {
    async validateUrl(urlStr: string): Promise<SsrfResult> {
      // 1. Parse URL
      const url = parseUrl(urlStr);
      if (!url) {
        return { safe: false, reason: 'Invalid URL' };
      }

      // 2. Only allow http/https
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { safe: false, reason: `Blocked protocol: ${url.protocol}` };
      }

      const hostname = url.hostname.replace(/^\[|\]$/g, '');

      // 3. Check hostname allowlist (if configured)
      if (allowedHostnames && allowedHostnames.length > 0) {
        if (!allowedHostnames.some(h => h.toLowerCase() === hostname.toLowerCase())) {
          return { safe: false, reason: `Hostname not in allowlist: ${hostname}`, hostname };
        }
      }

      // 4. Check blocked hostnames
      if (isBlockedHostname(hostname, blockedHostnames)) {
        return { safe: false, reason: `Blocked hostname: ${hostname}`, hostname };
      }

      // 5. If hostname is already an IP, check directly
      if (isIP(hostname)) {
        if (!allowPrivateNetwork && isPrivateIp(hostname)) {
          return { safe: false, reason: `Private IP address: ${hostname}`, hostname, resolvedIp: hostname };
        }
        return { safe: true, hostname, resolvedIp: hostname };
      }

      // 6. DNS resolution (with pinning)
      if (pinDns) {
        const ips = await resolveHost(hostname);
        if (ips.length === 0) {
          return { safe: false, reason: `DNS resolution failed: ${hostname}`, hostname };
        }

        // Check ALL resolved IPs
        for (const ip of ips) {
          if (!allowPrivateNetwork && isPrivateIp(ip)) {
            return {
              safe: false,
              reason: `Hostname ${hostname} resolves to private IP: ${ip}`,
              hostname,
              resolvedIp: ip,
            };
          }
        }

        // Pin first resolved IP
        return { safe: true, hostname, resolvedIp: ips[0] };
      }

      return { safe: true, hostname };
    },
  };
}
