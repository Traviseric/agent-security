/**
 * Download Guard Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createDownloadGuard } from '../src/guards/download.js';

describe('createDownloadGuard', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('should reject when Content-Length exceeds limit', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({ 'content-length': '20000000' }),
      body: null,
    });

    const guard = createDownloadGuard({ maxBodyBytes: 10 * 1024 * 1024 });
    const result = await guard.fetch('https://example.com/huge-file');
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('Content-Length');
    expect(result.reason).toContain('exceeds limit');
  });

  it('should accept response within size limit', async () => {
    const body = Buffer.from('hello world');
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({ 'content-length': String(body.length), 'content-type': 'text/plain' }),
      body: stream,
    });

    const guard = createDownloadGuard({ maxBodyBytes: 1024 });
    const result = await guard.fetch('https://example.com/small.txt');
    expect(result.ok).toBe(true);
    expect(result.data!.toString()).toBe('hello world');
    expect(result.contentType).toBe('text/plain');
  });

  it('should abort streaming body that exceeds limit', async () => {
    const chunks = [
      Buffer.alloc(500, 'a'),
      Buffer.alloc(600, 'b'), // total 1100 > 1000
    ];
    let chunkIndex = 0;

    const stream = new ReadableStream({
      pull(controller) {
        if (chunkIndex < chunks.length) {
          controller.enqueue(chunks[chunkIndex++]);
        } else {
          controller.close();
        }
      },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({}), // No content-length — chunked
      body: stream,
    });

    const guard = createDownloadGuard({ maxBodyBytes: 1000 });
    const result = await guard.fetch('https://example.com/chunked');
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('exceeded');
  });

  it('should reject disallowed content types', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({ 'content-type': 'application/octet-stream', 'content-length': '100' }),
      body: null,
    });

    const guard = createDownloadGuard({
      allowedContentTypes: ['application/json', 'text/html'],
    });
    const result = await guard.fetch('https://example.com/binary');
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('Content type');
    expect(result.reason).toContain('not in allowed');
  });

  it('should accept allowed content types', async () => {
    const body = Buffer.from('{"ok": true}');
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({ 'content-type': 'application/json; charset=utf-8', 'content-length': String(body.length) }),
      body: stream,
    });

    const guard = createDownloadGuard({
      allowedContentTypes: ['application/json'],
    });
    const result = await guard.fetch('https://example.com/api');
    expect(result.ok).toBe(true);
  });

  it('should handle empty body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      headers: new Headers({}),
      body: null,
    });

    const guard = createDownloadGuard();
    const result = await guard.fetch('https://example.com/empty');
    expect(result.ok).toBe(true);
    expect(result.contentLength).toBe(0);
  });

  it('should handle fetch errors', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    const guard = createDownloadGuard();
    const result = await guard.fetch('https://unreachable.example.com');
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('Fetch failed');
  });
});
