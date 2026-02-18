/**
 * Path Traversal Validator Tests
 */

import { describe, it, expect } from 'vitest';
import { validatePathWithinRoot, PathTraversalError } from '../src/guards/fs-safe.js';

describe('validatePathWithinRoot', () => {
  const root = process.platform === 'win32' ? 'C:\\sandbox' : '/sandbox';

  it('should allow paths within root', () => {
    const result = validatePathWithinRoot(root, 'data/config.json');
    expect(result.safe).toBe(true);
    expect(result.resolvedPath).toContain('config.json');
  });

  it('should allow nested paths', () => {
    const result = validatePathWithinRoot(root, 'a/b/c/d.txt');
    expect(result.safe).toBe(true);
  });

  it('should block path traversal with ../', () => {
    const result = validatePathWithinRoot(root, '../../../etc/passwd');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('escapes root');
  });

  it('should block path traversal with encoded ../', () => {
    // resolve() handles normalized paths, so ../ in middle of path
    const result = validatePathWithinRoot(root, 'data/../../etc/passwd');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('escapes root');
  });

  it('should block null bytes', () => {
    const result = validatePathWithinRoot(root, 'data/file\0.txt');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Null byte');
  });

  it('should handle root path itself', () => {
    const result = validatePathWithinRoot(root, '.');
    expect(result.safe).toBe(true);
  });

  it('should block paths that look like root but extend it', () => {
    // e.g., /sandbox vs /sandboxExtra
    // This uses resolve so /sandbox/../sandboxExtra would escape
    const result = validatePathWithinRoot(root, '../sandboxExtra/file.txt');
    expect(result.safe).toBe(false);
  });

  it('should allow deeply nested safe paths', () => {
    const result = validatePathWithinRoot(root, 'a/b/c/d/e/f/g.txt');
    expect(result.safe).toBe(true);
  });
});

describe('PathTraversalError', () => {
  it('should contain path and root information', () => {
    const err = new PathTraversalError('test error', '../etc/passwd', '/sandbox');
    expect(err.name).toBe('PathTraversalError');
    expect(err.attemptedPath).toBe('../etc/passwd');
    expect(err.root).toBe('/sandbox');
    expect(err.message).toBe('test error');
  });
});
