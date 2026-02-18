/**
 * Path Traversal Validator (fs-safe)
 *
 * TOCTOU-safe file access within a root boundary. Validates that
 * file paths stay within the sandbox root, checks for symlinks,
 * and verifies inode consistency after open.
 *
 * Reference: OpenClaw src/infra/fs-safe.ts (103 lines)
 * Source: OPENCLAW_SECURITY_ANALYSIS.md, Category 1 (7 vulns)
 */

import { resolve, normalize, relative, sep } from 'node:path';
import { open, lstat, stat, realpath } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { constants } from 'node:fs';

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export interface FsSafeOptions {
  /** Sandbox root directory. All access must be within this path. */
  root: string;
  /** Allow symlinks at all. Default: false */
  allowSymlinks?: boolean;
  /** Allow symlinks only if target is within root. Default: false */
  followSymlinksInRoot?: boolean;
}

export interface FsSafeResult {
  safe: boolean;
  reason?: string;
  resolvedPath?: string;
}

export class PathTraversalError extends Error {
  constructor(
    message: string,
    public readonly attemptedPath: string,
    public readonly root: string,
  ) {
    super(message);
    this.name = 'PathTraversalError';
  }
}

// ═══════════════════════════════════════════════════════════
// Path Validation (no I/O)
// ═══════════════════════════════════════════════════════════

/**
 * Validate that a path stays within the root boundary.
 * Pure path-based check — no filesystem I/O.
 */
export function validatePathWithinRoot(root: string, targetPath: string): FsSafeResult {
  const normalizedRoot = normalize(resolve(root));
  const normalizedTarget = normalize(resolve(root, targetPath));

  // Must be within root + separator (prevents /rootExtra matching /root)
  if (!normalizedTarget.startsWith(normalizedRoot + sep) && normalizedTarget !== normalizedRoot) {
    return {
      safe: false,
      reason: `Path escapes root: "${targetPath}" resolves outside "${root}"`,
    };
  }

  // Check for null bytes (common injection in C-based filesystems)
  if (targetPath.includes('\0')) {
    return { safe: false, reason: 'Null byte in path' };
  }

  return { safe: true, resolvedPath: normalizedTarget };
}

// ═══════════════════════════════════════════════════════════
// Symlink Validation (requires I/O)
// ═══════════════════════════════════════════════════════════

/**
 * Check if a path is a symlink and validate according to policy.
 */
async function checkSymlink(
  fullPath: string,
  root: string,
  options: FsSafeOptions,
): Promise<FsSafeResult> {
  try {
    const lstats = await lstat(fullPath);

    if (!lstats.isSymbolicLink()) {
      // Not a symlink — check it's a regular file
      if (!lstats.isFile()) {
        return { safe: false, reason: `Not a regular file: ${fullPath}` };
      }
      return { safe: true, resolvedPath: fullPath };
    }

    // It's a symlink
    if (!options.allowSymlinks) {
      return { safe: false, reason: `Symlink not allowed: ${fullPath}` };
    }

    // If followSymlinksInRoot, resolve and check target is within root
    if (options.followSymlinksInRoot) {
      const realTarget = await realpath(fullPath);
      const normalizedRoot = normalize(resolve(root));

      if (!realTarget.startsWith(normalizedRoot + sep) && realTarget !== normalizedRoot) {
        return {
          safe: false,
          reason: `Symlink target escapes root: ${fullPath} -> ${realTarget}`,
          resolvedPath: realTarget,
        };
      }

      // Verify the target is a regular file
      const targetStats = await stat(realTarget);
      if (!targetStats.isFile()) {
        return { safe: false, reason: `Symlink target is not a regular file: ${realTarget}` };
      }

      return { safe: true, resolvedPath: realTarget };
    }

    return { safe: false, reason: `Symlink encountered and followSymlinksInRoot is false: ${fullPath}` };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { safe: false, reason: `Path does not exist: ${fullPath}` };
    }
    return { safe: false, reason: `Stat failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}

// ═══════════════════════════════════════════════════════════
// TOCTOU-Safe File Open
// ═══════════════════════════════════════════════════════════

/**
 * Open a file within the root boundary with TOCTOU protection.
 *
 * 1. Validate path string stays within root
 * 2. lstat to check for symlinks
 * 3. Open the file
 * 4. fstat the opened handle and verify inode matches
 *
 * @example
 * ```typescript
 * const handle = await openFileWithinRoot('/sandbox', 'data/config.json');
 * const content = await handle.readFile('utf-8');
 * await handle.close();
 * ```
 */
export async function openFileWithinRoot(
  root: string,
  relativePath: string,
  options?: Partial<FsSafeOptions>,
): Promise<FileHandle> {
  const opts: FsSafeOptions = {
    root,
    allowSymlinks: false,
    followSymlinksInRoot: false,
    ...options,
  };

  // Step 1: Pure path validation
  const pathResult = validatePathWithinRoot(root, relativePath);
  if (!pathResult.safe) {
    throw new PathTraversalError(
      pathResult.reason!,
      relativePath,
      root,
    );
  }

  const fullPath = pathResult.resolvedPath!;

  // Step 2: Symlink check via lstat
  const symlinkResult = await checkSymlink(fullPath, root, opts);
  if (!symlinkResult.safe) {
    throw new PathTraversalError(
      symlinkResult.reason!,
      relativePath,
      root,
    );
  }

  // Record pre-open inode for TOCTOU check
  const preOpenStats = await lstat(symlinkResult.resolvedPath || fullPath);
  const expectedIno = preOpenStats.ino;
  const expectedDev = preOpenStats.dev;

  // Step 3: Open the file
  // Use O_RDONLY. On platforms that support O_NOFOLLOW, we would add it here,
  // but Node.js doesn't expose O_NOFOLLOW directly. The lstat check above
  // provides equivalent protection.
  const handle = await open(fullPath, constants.O_RDONLY);

  // Step 4: TOCTOU defense — verify inode after open
  try {
    const postOpenStats = await handle.stat();

    if (postOpenStats.ino !== expectedIno || postOpenStats.dev !== expectedDev) {
      await handle.close();
      throw new PathTraversalError(
        `TOCTOU detected: inode changed between stat and open (expected ${expectedDev}:${expectedIno}, got ${postOpenStats.dev}:${postOpenStats.ino})`,
        relativePath,
        root,
      );
    }

    // Verify it's still a regular file (not swapped to device, directory, etc.)
    if (!postOpenStats.isFile()) {
      await handle.close();
      throw new PathTraversalError(
        'File type changed between stat and open — not a regular file',
        relativePath,
        root,
      );
    }
  } catch (err) {
    if (err instanceof PathTraversalError) throw err;
    await handle.close();
    throw err;
  }

  return handle;
}

/**
 * Validate a path without opening it. Useful for pre-flight checks.
 */
export async function validatePath(
  root: string,
  relativePath: string,
  options?: Partial<FsSafeOptions>,
): Promise<FsSafeResult> {
  const opts: FsSafeOptions = {
    root,
    allowSymlinks: false,
    followSymlinksInRoot: false,
    ...options,
  };

  const pathResult = validatePathWithinRoot(root, relativePath);
  if (!pathResult.safe) return pathResult;

  return checkSymlink(pathResult.resolvedPath!, root, opts);
}
