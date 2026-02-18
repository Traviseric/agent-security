/**
 * Download Guard Module
 *
 * Enforces size caps, timeouts, and content-type validation on
 * external HTTP fetches. Prevents memory exhaustion and slowloris
 * attacks from unbounded downloads.
 *
 * Reference: OpenClaw Category 6 — DoS / CWE-400 (4 vulns)
 * Source: OPENCLAW_SECURITY_ANALYSIS.md
 */

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export interface DownloadPolicy {
  /** Maximum response body size in bytes. Default: 10MB */
  maxBodyBytes?: number;
  /** Connection timeout in ms. Default: 10_000 */
  connectionTimeoutMs?: number;
  /** Total response timeout in ms. Default: 30_000 */
  responseTimeoutMs?: number;
  /** Allowed content types. If set, rejects other MIME types. */
  allowedContentTypes?: string[];
}

export interface DownloadResult {
  ok: boolean;
  data?: Buffer;
  contentType?: string;
  contentLength?: number;
  reason?: string;
}

export interface DownloadGuard {
  fetch(url: string, init?: RequestInit): Promise<DownloadResult>;
}

export class DownloadLimitExceededError extends Error {
  constructor(
    public readonly limit: number,
    public readonly actual?: number,
  ) {
    super(`Download size limit exceeded: ${actual ?? 'unknown'} bytes > ${limit} byte limit`);
    this.name = 'DownloadLimitExceededError';
  }
}

export class DownloadTimeoutError extends Error {
  constructor(
    public readonly timeoutMs: number,
    public readonly phase: 'connection' | 'response',
  ) {
    super(`Download ${phase} timeout after ${timeoutMs}ms`);
    this.name = 'DownloadTimeoutError';
  }
}

export class ContentTypeRejectedError extends Error {
  constructor(
    public readonly actual: string,
    public readonly allowed: string[],
  ) {
    super(`Content type rejected: "${actual}" not in [${allowed.join(', ')}]`);
    this.name = 'ContentTypeRejectedError';
  }
}

// ═══════════════════════════════════════════════════════════
// Default Policy
// ═══════════════════════════════════════════════════════════

const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024; // 10MB
const DEFAULT_CONNECTION_TIMEOUT_MS = 10_000;
const DEFAULT_RESPONSE_TIMEOUT_MS = 30_000;

// ═══════════════════════════════════════════════════════════
// Guard Factory
// ═══════════════════════════════════════════════════════════

/**
 * Create a download guard with size caps and timeouts.
 *
 * @example
 * ```typescript
 * const guard = createDownloadGuard({ maxBodyBytes: 5 * 1024 * 1024 });
 * const result = await guard.fetch('https://example.com/data.json');
 * if (!result.ok) throw new Error(result.reason);
 * ```
 */
export function createDownloadGuard(policy: DownloadPolicy = {}): DownloadGuard {
  const {
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    connectionTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS,
    responseTimeoutMs = DEFAULT_RESPONSE_TIMEOUT_MS,
    allowedContentTypes,
  } = policy;

  return {
    async fetch(url: string, init?: RequestInit): Promise<DownloadResult> {
      // Create abort controller for timeout management
      const controller = new AbortController();
      const { signal } = controller;

      // Merge with any existing signal
      if (init?.signal) {
        init.signal.addEventListener('abort', () => controller.abort(init.signal!.reason));
      }

      // Connection timeout
      const connectionTimer = setTimeout(() => {
        controller.abort(new DownloadTimeoutError(connectionTimeoutMs, 'connection'));
      }, connectionTimeoutMs);

      let response: Response;
      try {
        response = await globalThis.fetch(url, { ...init, signal });
      } catch (err) {
        clearTimeout(connectionTimer);
        if (err instanceof DownloadTimeoutError) {
          return { ok: false, reason: err.message };
        }
        if (signal.aborted) {
          return { ok: false, reason: `Connection timeout after ${connectionTimeoutMs}ms` };
        }
        return { ok: false, reason: `Fetch failed: ${err instanceof Error ? err.message : String(err)}` };
      }
      clearTimeout(connectionTimer);

      // Check Content-Length header before reading body
      const contentLengthHeader = response.headers.get('content-length');
      const contentLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : undefined;
      if (contentLength !== undefined && contentLength > maxBodyBytes) {
        controller.abort();
        return {
          ok: false,
          contentLength,
          reason: `Content-Length ${contentLength} exceeds limit ${maxBodyBytes}`,
        };
      }

      // Check content type
      const contentType = response.headers.get('content-type') || '';
      if (allowedContentTypes && allowedContentTypes.length > 0) {
        const mimeType = contentType.split(';')[0].trim().toLowerCase();
        if (!allowedContentTypes.some(ct => ct.toLowerCase() === mimeType)) {
          controller.abort();
          return {
            ok: false,
            contentType,
            reason: `Content type "${mimeType}" not in allowed types`,
          };
        }
      }

      // Response timeout for body reading
      const responseTimer = setTimeout(() => {
        controller.abort(new DownloadTimeoutError(responseTimeoutMs, 'response'));
      }, responseTimeoutMs);

      // Stream body with size limit
      try {
        if (!response.body) {
          clearTimeout(responseTimer);
          return { ok: true, data: Buffer.alloc(0), contentType, contentLength: 0 };
        }

        const chunks: Uint8Array[] = [];
        let totalSize = 0;
        const reader = response.body.getReader();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          totalSize += value.byteLength;
          if (totalSize > maxBodyBytes) {
            reader.cancel();
            clearTimeout(responseTimer);
            return {
              ok: false,
              contentLength: totalSize,
              reason: `Response body exceeded ${maxBodyBytes} byte limit at ${totalSize} bytes`,
            };
          }

          chunks.push(value);
        }

        clearTimeout(responseTimer);
        return {
          ok: true,
          data: Buffer.concat(chunks),
          contentType,
          contentLength: totalSize,
        };
      } catch (err) {
        clearTimeout(responseTimer);
        if (err instanceof DownloadTimeoutError) {
          return { ok: false, reason: err.message };
        }
        if (signal.aborted) {
          return { ok: false, reason: `Response timeout after ${responseTimeoutMs}ms` };
        }
        return { ok: false, reason: `Body read failed: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  };
}
