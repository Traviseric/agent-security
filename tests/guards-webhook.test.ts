/**
 * Webhook Verifier Tests
 */

import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import {
  verifyGitHubWebhook,
  verifySlackWebhook,
  verifyStripeWebhook,
  createHmacVerifier,
} from '../src/guards/webhook.js';

describe('verifyGitHubWebhook', () => {
  const secret = 'test-github-secret';
  const payload = '{"action":"push","ref":"refs/heads/main"}';

  function makeGitHubSignature(body: string, key: string): string {
    return 'sha256=' + createHmac('sha256', key).update(body).digest('hex');
  }

  it('should verify valid signature', () => {
    const sig = makeGitHubSignature(payload, secret);
    const result = verifyGitHubWebhook(payload, sig, secret);
    expect(result.valid).toBe(true);
  });

  it('should reject invalid signature', () => {
    const result = verifyGitHubWebhook(payload, 'sha256=deadbeef', secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('mismatch');
  });

  it('should reject missing signature', () => {
    const result = verifyGitHubWebhook(payload, '', secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing');
  });

  it('should reject wrong prefix', () => {
    const sig = 'sha1=' + createHmac('sha256', secret).update(payload).digest('hex');
    const result = verifyGitHubWebhook(payload, sig, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('prefix');
  });

  it('should reject wrong secret', () => {
    const sig = makeGitHubSignature(payload, 'wrong-secret');
    const result = verifyGitHubWebhook(payload, sig, secret);
    expect(result.valid).toBe(false);
  });

  it('should handle Buffer payload', () => {
    const buf = Buffer.from(payload);
    const sig = makeGitHubSignature(payload, secret);
    const result = verifyGitHubWebhook(buf, sig, secret);
    expect(result.valid).toBe(true);
  });
});

describe('verifySlackWebhook', () => {
  const secret = 'test-slack-secret';
  const payload = 'token=abc&command=/test';
  const timestamp = String(Math.floor(Date.now() / 1000));

  function makeSlackSignature(body: string, ts: string, key: string): string {
    const sigBase = `v0:${ts}:${body}`;
    return 'v0=' + createHmac('sha256', key).update(sigBase).digest('hex');
  }

  it('should verify valid signature', () => {
    const sig = makeSlackSignature(payload, timestamp, secret);
    const result = verifySlackWebhook(payload, sig, timestamp, secret);
    expect(result.valid).toBe(true);
  });

  it('should reject invalid signature', () => {
    const result = verifySlackWebhook(payload, 'v0=deadbeef', timestamp, secret);
    expect(result.valid).toBe(false);
  });

  it('should reject old timestamps (replay protection)', () => {
    const oldTimestamp = String(Math.floor(Date.now() / 1000) - 600); // 10 minutes old
    const sig = makeSlackSignature(payload, oldTimestamp, secret);
    const result = verifySlackWebhook(payload, sig, oldTimestamp, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Timestamp too old');
  });

  it('should reject missing timestamp', () => {
    const result = verifySlackWebhook(payload, 'v0=test', '', secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing timestamp');
  });
});

describe('verifyStripeWebhook', () => {
  const secret = 'whsec_test123';
  const payload = '{"type":"payment_intent.succeeded"}';
  const timestamp = String(Math.floor(Date.now() / 1000));

  function makeStripeSignature(body: string, ts: string, key: string): string {
    const signedPayload = `${ts}.${body}`;
    const sig = createHmac('sha256', key).update(signedPayload).digest('hex');
    return `t=${ts},v1=${sig}`;
  }

  it('should verify valid signature', () => {
    const sigHeader = makeStripeSignature(payload, timestamp, secret);
    const result = verifyStripeWebhook(payload, sigHeader, secret);
    expect(result.valid).toBe(true);
  });

  it('should reject invalid signature', () => {
    const result = verifyStripeWebhook(payload, `t=${timestamp},v1=deadbeef`, secret);
    expect(result.valid).toBe(false);
  });

  it('should reject missing header', () => {
    const result = verifyStripeWebhook(payload, '', secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing');
  });

  it('should reject malformed header', () => {
    const result = verifyStripeWebhook(payload, 'invalid-header', secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Invalid');
  });

  it('should reject old timestamps', () => {
    const oldTimestamp = String(Math.floor(Date.now() / 1000) - 600);
    const sigHeader = makeStripeSignature(payload, oldTimestamp, secret);
    const result = verifyStripeWebhook(payload, sigHeader, secret, 300);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Timestamp outside tolerance');
  });
});

describe('createHmacVerifier', () => {
  const secret = 'generic-secret';
  const payload = 'test payload';

  it('should verify with custom prefix', () => {
    const sig = 'hmac=' + createHmac('sha256', secret).update(payload).digest('hex');
    const verifier = createHmacVerifier('sha256', secret, 'hmac=');
    const result = verifier.verify(payload, sig);
    expect(result.valid).toBe(true);
  });

  it('should verify without prefix', () => {
    const sig = createHmac('sha256', secret).update(payload).digest('hex');
    const verifier = createHmacVerifier('sha256', secret);
    const result = verifier.verify(payload, sig);
    expect(result.valid).toBe(true);
  });

  it('should reject missing signature', () => {
    const verifier = createHmacVerifier('sha256', secret);
    const result = verifier.verify(payload, '');
    expect(result.valid).toBe(false);
  });
});
