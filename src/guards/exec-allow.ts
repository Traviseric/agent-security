/**
 * Exec Allowlist Module
 *
 * Default-deny execution guard with resolved binary path matching,
 * dangerous environment variable filtering, and platform-specific
 * evasion detection.
 *
 * Reference: OpenClaw src/infra/exec-approvals.ts (540+ lines)
 * Source: OPENCLAW_SECURITY_ANALYSIS.md, Category 3 (8 vulns)
 */

import { resolve, basename, isAbsolute } from 'node:path';
import { existsSync, realpathSync } from 'node:fs';

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export type SecurityLevel = 'deny' | 'allowlist' | 'full';

export interface ExecPolicy {
  /** Security level. 'deny' blocks all, 'allowlist' uses safeBins, 'full' allows any. Default: 'deny' */
  securityLevel?: SecurityLevel;
  /** Default safe binaries that are always allowed in 'allowlist' mode. */
  safeBins?: string[];
  /** Additional allowed binaries beyond safeBins. */
  customAllowlist?: string[];
  /** Environment variables to strip before execution. */
  blockedEnvVars?: string[];
  /** Resolve binary to absolute path before matching. Default: true */
  resolveBeforeMatch?: boolean;
}

export interface ExecDecision {
  allowed: boolean;
  reason: string;
  resolvedPath?: string;
  blockedEnvVars?: string[];
  sanitizedEnv?: Record<string, string>;
}

export interface ExecAllowlist {
  canExecute(command: string, args?: string[], env?: Record<string, string>): ExecDecision;
  addToAllowlist(binary: string): void;
  removeFromAllowlist(binary: string): void;
  getAllowlist(): string[];
}

// ═══════════════════════════════════════════════════════════
// Defaults
// ═══════════════════════════════════════════════════════════

const DEFAULT_SAFE_BINS = [
  'jq', 'grep', 'egrep', 'fgrep', 'cut', 'sort', 'uniq',
  'head', 'tail', 'tr', 'wc', 'cat', 'echo', 'printf',
  'ls', 'pwd', 'whoami', 'date', 'hostname',
  'sha256sum', 'sha512sum', 'md5sum', 'base64',
  'node', 'npm', 'npx', 'pnpm',
  'python3', 'python', 'pip', 'pip3',
  'git',
];

const DEFAULT_BLOCKED_ENV_VARS = [
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_FRAMEWORK_PATH',
  'DYLD_LIBRARY_PATH',
  'DYLD_FALLBACK_LIBRARY_PATH',
];

// ═══════════════════════════════════════════════════════════
// Evasion Detection
// ═══════════════════════════════════════════════════════════

/**
 * Detect Windows command chaining evasion in arguments.
 * cmd.exe /c "safe & evil" or "safe | evil"
 */
function detectWindowsCmdEvasion(command: string, args: string[]): string | null {
  const cmdBase = basename(command).toLowerCase();
  if (cmdBase !== 'cmd' && cmdBase !== 'cmd.exe') return null;

  const joined = args.join(' ');
  if (/[&|]/.test(joined)) {
    return `Command chaining detected in cmd.exe arguments: ${joined.substring(0, 80)}`;
  }
  return null;
}

/**
 * Detect encoded PowerShell command evasion.
 */
function detectPowershellEvasion(command: string, args: string[]): string | null {
  const cmdBase = basename(command).toLowerCase();
  if (cmdBase !== 'powershell' && cmdBase !== 'powershell.exe' && cmdBase !== 'pwsh' && cmdBase !== 'pwsh.exe') return null;

  for (const arg of args) {
    const lower = arg.toLowerCase();
    if (lower === '-encodedcommand' || lower === '-ec' || lower === '-e') {
      return 'PowerShell -EncodedCommand detected — commands must be plaintext for auditability';
    }
  }
  return null;
}

/**
 * Detect shell metacharacters in arguments that could enable injection.
 */
function detectShellMetachars(args: string[]): string | null {
  for (const arg of args) {
    if (/[;`$()]/.test(arg) && !arg.startsWith('-')) {
      return `Shell metacharacter detected in argument: "${arg.substring(0, 40)}"`;
    }
  }
  return null;
}

/**
 * Detect PATH-like override in environment.
 */
function detectPathOverride(env: Record<string, string>): string | null {
  const path = env['PATH'];
  if (path && /^(?:\/tmp|\/dev|\.|\.\.)/.test(path)) {
    return `Suspicious PATH override: "${path.substring(0, 60)}"`;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════
// Binary Resolution
// ═══════════════════════════════════════════════════════════

/**
 * Attempt to resolve a binary name to its absolute path.
 * On failure, returns the original command.
 */
function resolveBinary(command: string): string {
  if (isAbsolute(command)) {
    try {
      return realpathSync(command);
    } catch {
      return command;
    }
  }

  // Try to find in PATH
  const pathEnv = process.env.PATH || '';
  const separator = process.platform === 'win32' ? ';' : ':';
  const extensions = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', '.com', ''] : [''];
  const dirs = pathEnv.split(separator);

  for (const dir of dirs) {
    for (const ext of extensions) {
      const candidate = resolve(dir, command + ext);
      if (existsSync(candidate)) {
        try {
          return realpathSync(candidate);
        } catch {
          return candidate;
        }
      }
    }
  }

  return command;
}

// ═══════════════════════════════════════════════════════════
// Guard Factory
// ═══════════════════════════════════════════════════════════

/**
 * Create an exec allowlist guard.
 *
 * @example
 * ```typescript
 * const guard = createExecAllowlist({ securityLevel: 'allowlist' });
 * const decision = guard.canExecute('git', ['status']);
 * if (!decision.allowed) throw new Error(decision.reason);
 * ```
 */
export function createExecAllowlist(policy: ExecPolicy = {}): ExecAllowlist {
  const {
    securityLevel = 'deny',
    safeBins = DEFAULT_SAFE_BINS,
    customAllowlist = [],
    blockedEnvVars = DEFAULT_BLOCKED_ENV_VARS,
    resolveBeforeMatch = true,
  } = policy;

  const allowlist = new Set([...safeBins, ...customAllowlist]);

  return {
    canExecute(command: string, args: string[] = [], env?: Record<string, string>): ExecDecision {
      // Strip blocked env vars
      const strippedEnvVars: string[] = [];
      let sanitizedEnv: Record<string, string> | undefined;
      if (env) {
        sanitizedEnv = { ...env };
        for (const key of blockedEnvVars) {
          if (key in sanitizedEnv) {
            strippedEnvVars.push(key);
            delete sanitizedEnv[key];
          }
        }

        // Check for PATH override evasion
        const pathIssue = detectPathOverride(env);
        if (pathIssue) {
          return {
            allowed: false,
            reason: pathIssue,
            blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined,
          };
        }
      }

      // Full mode: allow everything (after env sanitization)
      if (securityLevel === 'full') {
        return {
          allowed: true,
          reason: 'Security level: full (all commands allowed)',
          blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined,
          sanitizedEnv,
        };
      }

      // Deny mode: block everything
      if (securityLevel === 'deny') {
        return {
          allowed: false,
          reason: 'Security level: deny (all execution blocked)',
          blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined,
        };
      }

      // Allowlist mode: resolve + check

      // Platform-specific evasion checks
      const cmdEvasion = detectWindowsCmdEvasion(command, args);
      if (cmdEvasion) {
        return { allowed: false, reason: cmdEvasion, blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined };
      }

      const psEvasion = detectPowershellEvasion(command, args);
      if (psEvasion) {
        return { allowed: false, reason: psEvasion, blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined };
      }

      const shellEvasion = detectShellMetachars(args);
      if (shellEvasion) {
        return { allowed: false, reason: shellEvasion, blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined };
      }

      // Resolve binary path
      const resolvedPath = resolveBeforeMatch ? resolveBinary(command) : command;
      const binaryName = basename(resolvedPath).replace(/\.\w+$/, '').toLowerCase();
      const commandName = basename(command).replace(/\.\w+$/, '').toLowerCase();

      // Check against allowlist (match by name, not full path)
      const isAllowed = allowlist.has(binaryName) || allowlist.has(commandName);

      return {
        allowed: isAllowed,
        reason: isAllowed
          ? `Binary "${commandName}" is in the allowlist`
          : `Binary "${commandName}" is not in the allowlist`,
        resolvedPath: resolveBeforeMatch ? resolvedPath : undefined,
        blockedEnvVars: strippedEnvVars.length > 0 ? strippedEnvVars : undefined,
        sanitizedEnv,
      };
    },

    addToAllowlist(binary: string): void {
      allowlist.add(binary.toLowerCase());
    },

    removeFromAllowlist(binary: string): void {
      allowlist.delete(binary.toLowerCase());
    },

    getAllowlist(): string[] {
      return [...allowlist];
    },
  };
}
