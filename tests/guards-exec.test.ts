/**
 * Exec Allowlist Tests
 */

import { describe, it, expect } from 'vitest';
import { createExecAllowlist } from '../src/guards/exec-allow.js';

describe('createExecAllowlist', () => {
  describe('deny mode', () => {
    it('should block all execution', () => {
      const guard = createExecAllowlist({ securityLevel: 'deny' });
      const result = guard.canExecute('ls');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('deny');
    });
  });

  describe('full mode', () => {
    it('should allow all execution', () => {
      const guard = createExecAllowlist({ securityLevel: 'full' });
      const result = guard.canExecute('rm', ['-rf', '/']);
      expect(result.allowed).toBe(true);
    });

    it('should still strip dangerous env vars', () => {
      const guard = createExecAllowlist({ securityLevel: 'full' });
      const result = guard.canExecute('ls', [], { LD_PRELOAD: '/evil.so', HOME: '/home/user' });
      expect(result.allowed).toBe(true);
      expect(result.blockedEnvVars).toContain('LD_PRELOAD');
      expect(result.sanitizedEnv).not.toHaveProperty('LD_PRELOAD');
      expect(result.sanitizedEnv).toHaveProperty('HOME');
    });
  });

  describe('allowlist mode', () => {
    it('should allow safe binaries', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('git', ['status']);
      expect(result.allowed).toBe(true);
    });

    it('should block unknown binaries', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('evil-binary', ['--flag']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('not in the allowlist');
    });

    it('should allow custom allowlist entries', () => {
      const guard = createExecAllowlist({
        securityLevel: 'allowlist',
        customAllowlist: ['nmap'],
      });
      const result = guard.canExecute('nmap', ['-sV', 'target']);
      expect(result.allowed).toBe(true);
    });

    it('should detect Windows cmd.exe chaining', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('cmd.exe', ['/c', 'safe & evil']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Command chaining');
    });

    it('should detect cmd pipe chaining', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('cmd', ['/c', 'dir | evil']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Command chaining');
    });

    it('should detect PowerShell -EncodedCommand', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('powershell', ['-EncodedCommand', 'SGVsbG8=']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('EncodedCommand');
    });

    it('should detect PowerShell short flag -ec', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('pwsh', ['-ec', 'SGVsbG8=']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('EncodedCommand');
    });

    it('should detect shell metacharacters in args', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('grep', ['pattern; rm -rf /']);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Shell metacharacter');
    });

    it('should strip LD_PRELOAD from env', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('git', ['status'], { LD_PRELOAD: '/evil.so' });
      expect(result.blockedEnvVars).toContain('LD_PRELOAD');
    });

    it('should strip DYLD_INSERT_LIBRARIES from env', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('git', ['status'], { DYLD_INSERT_LIBRARIES: '/evil.dylib' });
      expect(result.blockedEnvVars).toContain('DYLD_INSERT_LIBRARIES');
    });

    it('should detect suspicious PATH override', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist' });
      const result = guard.canExecute('git', ['status'], { PATH: '/tmp/evil:$PATH' });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('PATH override');
    });
  });

  describe('allowlist management', () => {
    it('should support adding to allowlist', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist', safeBins: [] });
      expect(guard.canExecute('custom-tool').allowed).toBe(false);
      guard.addToAllowlist('custom-tool');
      expect(guard.canExecute('custom-tool').allowed).toBe(true);
    });

    it('should support removing from allowlist', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist', safeBins: ['git'] });
      expect(guard.canExecute('git').allowed).toBe(true);
      guard.removeFromAllowlist('git');
      expect(guard.canExecute('git').allowed).toBe(false);
    });

    it('should list current allowlist', () => {
      const guard = createExecAllowlist({ securityLevel: 'allowlist', safeBins: ['a', 'b'], customAllowlist: ['c'] });
      const list = guard.getAllowlist();
      expect(list).toContain('a');
      expect(list).toContain('b');
      expect(list).toContain('c');
    });
  });
});
