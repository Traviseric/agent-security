/**
 * Agent Security Pattern Library
 *
 * Comprehensive collection of 190 detection patterns for AI agent security
 * scanning, compiled from 19+ authoritative research sources.
 *
 * Pattern Categories:
 * - Prompt Injection (instruction override, role manipulation, boundary escape)
 * - Agent-Specific Attacks (CAPE, MCP, RAG poisoning, goal hijacking)
 * - Code Execution (RCE, argument injection, SSRF)
 * - OWASP Agentic Top 10 (ASI01-ASI10)
 * - Credential Detection
 * - Defense Evasion
 * - MCP Security Checklist (SlowMist - 44 patterns across 9 categories)
 */

// Export types
export * from './types.js';

// Export pattern groups
export * from './injection.js';
export * from './agent-attacks.js';
export * from './rce.js';
export * from './owasp-asi.js';
export * from './credentials.js';
export * from './defense-evasion.js';
export * from './mcp-checklist.js';
export * from './infrastructure.js';

// Import all patterns for combined export
import { allInjectionPatterns } from './injection.js';
import { allAgentAttackPatterns } from './agent-attacks.js';
import { allRcePatterns } from './rce.js';
import { allOwaspAsiPatterns } from './owasp-asi.js';
import { allCredentialPatterns } from './credentials.js';
import { allDefenseEvasionPatterns } from './defense-evasion.js';
import { allMcpChecklistPatterns } from './mcp-checklist.js';
import { allInfrastructurePatterns } from './infrastructure.js';

import type { DetectionPattern, AttackCategory, Severity } from './types.js';

/**
 * All patterns combined - the complete pattern library
 */
export const ALL_PATTERNS: DetectionPattern[] = [
  ...allInjectionPatterns,
  ...allAgentAttackPatterns,
  ...allRcePatterns,
  ...allOwaspAsiPatterns,
  ...allCredentialPatterns,
  ...allDefenseEvasionPatterns,
  ...allMcpChecklistPatterns,
  ...allInfrastructurePatterns,
];

/**
 * Get patterns by category
 */
export function getPatternsByCategory(category: AttackCategory): DetectionPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns by severity
 */
export function getPatternsBySeverity(severity: Severity): DetectionPattern[] {
  return ALL_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Get patterns by minimum severity
 */
export function getPatternsMinSeverity(minSeverity: Severity): DetectionPattern[] {
  const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
  const minIndex = severityOrder.indexOf(minSeverity);
  return ALL_PATTERNS.filter((p) => severityOrder.indexOf(p.severity) >= minIndex);
}

/**
 * Get patterns by source
 */
export function getPatternsBySource(source: string): DetectionPattern[] {
  return ALL_PATTERNS.filter((p) => p.source === source);
}

/**
 * Get patterns by OWASP ASI ID
 */
export function getPatternsByOwaspAsi(asiId: string): DetectionPattern[] {
  return ALL_PATTERNS.filter((p) => p.owaspAsi === asiId);
}

/**
 * Get patterns for a specific context
 */
export function getPatternsForContext(context: string): DetectionPattern[] {
  return ALL_PATTERNS.filter((p) => !p.context || p.context === 'any' || p.context === context);
}

/**
 * Pattern statistics
 */
export function getPatternStats(): {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  byOwaspAsi: Record<string, number>;
} {
  const stats = {
    total: ALL_PATTERNS.length,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    } as Record<Severity, number>,
    byCategory: {} as Record<string, number>,
    byOwaspAsi: {} as Record<string, number>,
  };

  for (const pattern of ALL_PATTERNS) {
    stats.bySeverity[pattern.severity]++;
    stats.byCategory[pattern.category] = (stats.byCategory[pattern.category] || 0) + 1;
    if (pattern.owaspAsi) {
      stats.byOwaspAsi[pattern.owaspAsi] = (stats.byOwaspAsi[pattern.owaspAsi] || 0) + 1;
    }
  }

  return stats;
}

/**
 * Search patterns by name or description
 */
export function searchPatterns(query: string): DetectionPattern[] {
  const lowerQuery = query.toLowerCase();
  return ALL_PATTERNS.filter(
    (p) =>
      p.name.toLowerCase().includes(lowerQuery) ||
      p.description.toLowerCase().includes(lowerQuery)
  );
}

// Re-export commonly used pattern groups for convenience
export {
  allInjectionPatterns,
  allAgentAttackPatterns,
  allRcePatterns,
  allOwaspAsiPatterns,
  allCredentialPatterns,
  allDefenseEvasionPatterns,
  allMcpChecklistPatterns,
  allInfrastructurePatterns,
};
