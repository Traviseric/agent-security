/**
 * Runtime Security Guards
 *
 * Importable security modules for use across the monorepo.
 * Each guard module provides runtime protection against a
 * specific class of vulnerability.
 */

export {
  createSsrfGuard,
  isPrivateIp,
  isPrivateIpv4,
  isPrivateIpv6,
  type SsrfPolicy,
  type SsrfResult,
  type SsrfGuard,
} from './ssrf.js';

export {
  createDownloadGuard,
  DownloadLimitExceededError,
  DownloadTimeoutError,
  ContentTypeRejectedError,
  type DownloadPolicy,
  type DownloadResult,
  type DownloadGuard,
} from './download.js';

export {
  createExecAllowlist,
  type ExecPolicy,
  type ExecDecision,
  type ExecAllowlist,
  type SecurityLevel,
} from './exec-allow.js';

export {
  openFileWithinRoot,
  validatePathWithinRoot,
  validatePath,
  PathTraversalError,
  type FsSafeOptions,
  type FsSafeResult,
} from './fs-safe.js';

export {
  verifyGitHubWebhook,
  verifySlackWebhook,
  verifyStripeWebhook,
  createHmacVerifier,
  type WebhookVerifyResult,
  type WebhookVerifier,
} from './webhook.js';
