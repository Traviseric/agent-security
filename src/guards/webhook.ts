/**
 * Webhook Verifier Module
 *
 * Timing-safe HMAC verification for webhook signatures from
 * GitHub, Slack, Stripe, and custom providers.
 *
 * All comparisons use crypto.timingSafeEqual() — never === for
 * HMAC/signature comparison (prevents timing attacks).
 *
 * Reference: OpenClaw extensions/voice-call/src/webhook-security.ts
 * Source: OPENCLAW_SECURITY_ANALYSIS.md, Category 8 (2 vulns)
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export interface WebhookVerifyResult {
  valid: boolean;
  reason?: string;
}

export interface WebhookVerifier {
  verify(payload: string | Buffer, signature: string): WebhookVerifyResult;
}

// ═══════════════════════════════════════════════════════════
// Core: Timing-Safe HMAC Comparison
// ═══════════════════════════════════════════════════════════

/**
 * Compute HMAC and compare timing-safely.
 */
function timingSafeHmacCompare(
  payload: string | Buffer,
  signature: string,
  secret: string,
  algorithm: string,
  prefix: string = '',
): boolean {
  const hmac = createHmac(algorithm, secret)
    .update(payload)
    .digest('hex');

  const expected = prefix + hmac;

  // Both must be same length for timingSafeEqual
  if (expected.length !== signature.length) return false;

  return timingSafeEqual(
    Buffer.from(expected, 'utf-8'),
    Buffer.from(signature, 'utf-8'),
  );
}

// ═══════════════════════════════════════════════════════════
// GitHub Webhook Verification
// ═══════════════════════════════════════════════════════════

/**
 * Verify a GitHub webhook signature (X-Hub-Signature-256).
 *
 * @example
 * ```typescript
 * const isValid = verifyGitHubWebhook(body, req.headers['x-hub-signature-256'], SECRET);
 * if (!isValid.valid) return res.status(401).json({ error: 'Invalid signature' });
 * ```
 */
export function verifyGitHubWebhook(
  payload: string | Buffer,
  signature: string,
  secret: string,
): WebhookVerifyResult {
  if (!signature) {
    return { valid: false, reason: 'Missing signature header' };
  }

  if (!signature.startsWith('sha256=')) {
    return { valid: false, reason: 'Invalid signature format: expected sha256= prefix' };
  }

  const valid = timingSafeHmacCompare(payload, signature, secret, 'sha256', 'sha256=');
  return valid
    ? { valid: true }
    : { valid: false, reason: 'Signature mismatch' };
}

// ═══════════════════════════════════════════════════════════
// Slack Webhook Verification
// ═══════════════════════════════════════════════════════════

/**
 * Verify a Slack webhook signature (X-Slack-Signature).
 * Requires the timestamp from X-Slack-Request-Timestamp header.
 *
 * @example
 * ```typescript
 * const isValid = verifySlackWebhook(body, signature, timestamp, SIGNING_SECRET);
 * ```
 */
export function verifySlackWebhook(
  payload: string | Buffer,
  signature: string,
  timestamp: string,
  secret: string,
): WebhookVerifyResult {
  if (!signature) {
    return { valid: false, reason: 'Missing signature header' };
  }

  if (!timestamp) {
    return { valid: false, reason: 'Missing timestamp header' };
  }

  // Reject timestamps older than 5 minutes (replay protection)
  const ts = parseInt(timestamp, 10);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > 300) {
    return { valid: false, reason: 'Timestamp too old (possible replay attack)' };
  }

  // Slack signature format: v0=HMAC(v0:timestamp:body)
  const sigBaseString = `v0:${timestamp}:${typeof payload === 'string' ? payload : payload.toString('utf-8')}`;
  const valid = timingSafeHmacCompare(sigBaseString, signature, secret, 'sha256', 'v0=');

  return valid
    ? { valid: true }
    : { valid: false, reason: 'Signature mismatch' };
}

// ═══════════════════════════════════════════════════════════
// Stripe Webhook Verification
// ═══════════════════════════════════════════════════════════

/**
 * Verify a Stripe webhook signature (Stripe-Signature header).
 *
 * @example
 * ```typescript
 * const isValid = verifyStripeWebhook(body, stripeSignature, WEBHOOK_SECRET);
 * ```
 */
export function verifyStripeWebhook(
  payload: string | Buffer,
  signatureHeader: string,
  secret: string,
  toleranceSec: number = 300,
): WebhookVerifyResult {
  if (!signatureHeader) {
    return { valid: false, reason: 'Missing signature header' };
  }

  // Parse Stripe signature header: "t=timestamp,v1=signature"
  const elements = signatureHeader.split(',');
  const pairs: Record<string, string> = {};
  for (const element of elements) {
    const [key, value] = element.split('=', 2);
    if (key && value) pairs[key] = value;
  }

  const timestamp = pairs['t'];
  const sig = pairs['v1'];

  if (!timestamp || !sig) {
    return { valid: false, reason: 'Invalid signature header format' };
  }

  // Replay protection
  const ts = parseInt(timestamp, 10);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > toleranceSec) {
    return { valid: false, reason: 'Timestamp outside tolerance (possible replay attack)' };
  }

  // Stripe signs: "timestamp.payload"
  const signedPayload = `${timestamp}.${typeof payload === 'string' ? payload : payload.toString('utf-8')}`;
  const expectedSig = createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');

  if (expectedSig.length !== sig.length) {
    return { valid: false, reason: 'Signature mismatch' };
  }

  const valid = timingSafeEqual(
    Buffer.from(expectedSig, 'utf-8'),
    Buffer.from(sig, 'utf-8'),
  );

  return valid
    ? { valid: true }
    : { valid: false, reason: 'Signature mismatch' };
}

// ═══════════════════════════════════════════════════════════
// Generic HMAC Verifier Factory
// ═══════════════════════════════════════════════════════════

/**
 * Create a generic HMAC webhook verifier.
 *
 * @example
 * ```typescript
 * const verifier = createHmacVerifier('sha256', 'my-secret', 'sha256=');
 * const result = verifier.verify(body, req.headers['x-signature']);
 * ```
 */
export function createHmacVerifier(
  algorithm: string,
  secret: string,
  signaturePrefix: string = '',
): WebhookVerifier {
  return {
    verify(payload: string | Buffer, signature: string): WebhookVerifyResult {
      if (!signature) {
        return { valid: false, reason: 'Missing signature' };
      }

      const valid = timingSafeHmacCompare(payload, signature, secret, algorithm, signaturePrefix);
      return valid
        ? { valid: true }
        : { valid: false, reason: 'Signature mismatch' };
    },
  };
}
