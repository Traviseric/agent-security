/**
 * Pattern Matching Engine
 *
 * Core engine for matching security patterns against content.
 * Includes:
 * - Context-aware filtering (file type → pattern context matching)
 * - Test file detection and severity downgrade
 * - Auto-classification of findings (why the finding exists)
 * - Taint proximity analysis (is user input near dangerous sinks?)
 * - Context flow tracing (does serialized context reach external tools?)
 */

import type {
  DetectionPattern,
  Finding,
  FindingClassification,
  MatchContext,
  RiskScore,
  Severity,
  ScanResult,
  TaintProximity,
} from '../patterns/types.js';

// ═══════════════════════════════════════════════════════════
// Context-Aware Filtering
// ═══════════════════════════════════════════════════════════

const RUNTIME_ONLY_CONTEXTS: MatchContext[] = [
  'file_write_operation',
  'file_create',
  'outbound_request',
  'email_operation',
  'url_parameter',
  'user_input',
];

const EXT_CONTEXT_MAP: Record<string, MatchContext> = {
  '.json': 'config', '.yaml': 'config', '.yml': 'config', '.toml': 'config',
  '.ini': 'config', '.cfg': 'config', '.conf': 'config', '.xml': 'config',
  '.ts': 'code', '.tsx': 'code', '.js': 'code', '.jsx': 'code',
  '.py': 'code', '.go': 'code', '.rs': 'code', '.java': 'code',
  '.c': 'code', '.cpp': 'code', '.rb': 'code',
  '.sh': 'code', '.bash': 'code', '.zsh': 'code', '.ps1': 'code',
  '.md': 'prompt', '.txt': 'prompt', '.rst': 'prompt',
};

const DEPENDENCY_FILE_PATTERNS = [
  /package\.json$/i, /requirements\.txt$/i, /Pipfile$/i,
  /Cargo\.toml$/i, /go\.mod$/i, /go\.sum$/i, /Gemfile$/i,
  /pom\.xml$/i, /build\.gradle$/i, /\.csproj$/i,
];

export function inferFileContext(filePath: string): MatchContext {
  const lower = filePath.toLowerCase().replace(/\\/g, '/');
  if (/\.env(?:\.\w+)?$/.test(lower)) return 'config';
  for (const depPattern of DEPENDENCY_FILE_PATTERNS) {
    if (depPattern.test(lower)) return 'dependency_version';
  }
  const ext = lower.match(/\.[^./\\]+$/)?.[0] || '';
  return EXT_CONTEXT_MAP[ext] || 'any';
}

export function shouldApplyPattern(pattern: DetectionPattern, filePath: string): boolean {
  const patternContext = pattern.context;
  if (!patternContext || patternContext === 'any') return true;
  if (RUNTIME_ONLY_CONTEXTS.includes(patternContext)) return false;

  const fileContext = inferFileContext(filePath);
  if (fileContext === 'any') return true;

  if (patternContext === 'dependency_version') return fileContext === 'dependency_version';
  if (patternContext === 'generated_code' || patternContext === 'command_template') return fileContext === 'code';
  if (patternContext === 'config') return fileContext === 'config' || fileContext === 'dependency_version';
  if (patternContext === 'code') return fileContext === 'code';
  if (patternContext === 'prompt') return fileContext === 'prompt';

  return true;
}

// ═══════════════════════════════════════════════════════════
// Test File Detection
// ═══════════════════════════════════════════════════════════

const TEST_PATH_PATTERNS = [
  /[/\\]tests?[/\\]/i,
  /[/\\]__tests__[/\\]/i,
  /[/\\]test_/i,
  /[/\\]spec[/\\]/i,
  /[/\\]fixtures?[/\\]/i,
  /[/\\]mocks?[/\\]/i,
  /[/\\]stubs?[/\\]/i,
  /[/\\]examples?[/\\]/i,
  /[/\\]e2e[/\\]/i,
  /[/\\]payloads?[/\\]/i,
  /[/\\]data[/\\]payloads?/i,
  /[/\\]resources[/\\]/i,
  /[/\\]samples?[/\\]/i,
  /\.test\.\w+$/i,
  /\.spec\.\w+$/i,
  /_test\.\w+$/i,
  /test_\w+\.\w+$/i,
  /\.fixture\.\w+$/i,
  /\.mock\.\w+$/i,
];

export function isTestFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return TEST_PATH_PATTERNS.some(p => p.test(normalized));
}

const SEVERITY_DOWNGRADE: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'low',
};

// ═══════════════════════════════════════════════════════════
// Auto-Classification
// ═══════════════════════════════════════════════════════════

const INJECTION_CATEGORIES = new Set([
  'instruction_override', 'role_manipulation', 'boundary_escape',
  'hierarchy_violation', 'goal_hijacking', 'rag_poisoning',
  'hidden_injection', 'stealth_instruction', 'session_smuggling',
  'behavior_manipulation', 'adversarial_suffix', 'prompt_extraction',
]);

const CREDENTIAL_CATEGORIES = new Set([
  'credential_exposure', 'credential_theft',
]);

const CONFIG_CATEGORIES = new Set([
  'config_vulnerability', 'permission_escalation',
  'container_misconfig', 'timing_attack',
]);

const ARCHITECTURAL_CATEGORIES = new Set([
  'cross_agent_escalation', 'mcp_attack', 'persistence',
  'ASI01_goal_hijack', 'ASI02_tool_misuse', 'ASI03_privilege_abuse',
  'ASI04_supply_chain', 'ASI06_memory_poisoning', 'ASI07_insecure_comms',
  'ASI08_cascading_failures', 'ASI09_trust_exploitation', 'ASI10_rogue_agents',
]);

const SUPPLY_CHAIN_PATTERNS = new Set([
  'mcp_version_unpinned', 'mcp_dependency_wildcard', 'mcp_unsigned_plugin',
  'mcp_install_untrusted_registry', 'mcp_no_tool_integrity_check',
  'readme_curl_pipe_sh', 'readme_wget_pipe_sh', 'readme_powershell_download',
  'readme_password_protected_archive',
]);

export function classifyFinding(finding: Finding): FindingClassification {
  const { pattern, isTestFile: inTestFile } = finding;

  // Test payloads: injection patterns found in test files of security tools
  if (inTestFile && INJECTION_CATEGORIES.has(pattern.category)) {
    return 'test_payload';
  }

  // Supply chain risks
  if (SUPPLY_CHAIN_PATTERNS.has(pattern.name) || pattern.category === 'ASI04_supply_chain') {
    return 'supply_chain_risk';
  }

  // Credential exposure
  if (CREDENTIAL_CATEGORIES.has(pattern.category)) {
    return 'credential_exposure';
  }

  // Configuration risks
  if (CONFIG_CATEGORIES.has(pattern.category)) {
    return 'configuration_risk';
  }

  // Architectural weaknesses
  if (ARCHITECTURAL_CATEGORIES.has(pattern.category)) {
    return 'architectural_weakness';
  }

  // Reconnaissance patterns
  if (pattern.category === 'reconnaissance') {
    return inTestFile ? 'test_payload' : 'live_vulnerability';
  }

  // Code execution patterns
  if (pattern.category === 'code_injection' || pattern.category === 'argument_injection' ||
      pattern.category === 'ssrf' || pattern.category === 'ASI05_rce' ||
      pattern.category === 'dangerous_commands' || pattern.category === 'env_injection') {
    return inTestFile ? 'test_payload' : 'live_vulnerability';
  }

  // Data exfiltration / defense evasion
  if (pattern.category === 'data_exfiltration' || pattern.category === 'defense_evasion' ||
      pattern.category === 'rendering_exfil') {
    return inTestFile ? 'test_payload' : 'live_vulnerability';
  }

  // URL reconstruction / path traversal
  if (pattern.category === 'url_reconstruction' || pattern.category === 'path_traversal') {
    return inTestFile ? 'test_payload' : 'live_vulnerability';
  }

  // Platform-specific attacks
  if (pattern.category === 'platform_specific') {
    return inTestFile ? 'test_payload' : 'live_vulnerability';
  }

  // Injection patterns in non-test files
  if (INJECTION_CATEGORIES.has(pattern.category)) {
    return 'live_vulnerability';
  }

  return 'unclassified';
}

// ═══════════════════════════════════════════════════════════
// Taint Proximity Analysis
// ═══════════════════════════════════════════════════════════

const TAINT_SINK_PATTERNS = new Set([
  'eval_exec_usage', 'dangerous_module_import', 'pickle_loads',
  'shell_true', 'langchain_import_bypass', 'langchain_palchain',
  'asi05_code_execution',
]);

const TAINT_SOURCE_REGEX = /(?:input\s*\(|request\.|req\.body|req\.query|req\.params|argv|sys\.stdin|process\.stdin|\.invoke\(|\.generate\(|\.complete\(|\.chat\(|user_input|user_message|prompt_text|raw_input|from_user)/i;

export function analyzeTaintProximity(
  lines: string[],
  sinkLineIndex: number,
  windowSize = 10
): TaintProximity {
  // Check the sink line itself
  if (TAINT_SOURCE_REGEX.test(lines[sinkLineIndex])) {
    return 'direct';
  }

  // Check surrounding lines within window
  const start = Math.max(0, sinkLineIndex - windowSize);
  const end = Math.min(lines.length, sinkLineIndex + windowSize + 1);

  for (let i = start; i < end; i++) {
    if (i === sinkLineIndex) continue;
    if (TAINT_SOURCE_REGEX.test(lines[i])) {
      return 'nearby';
    }
  }

  return 'distant';
}

// ═══════════════════════════════════════════════════════════
// Context Flow Tracing
// ═══════════════════════════════════════════════════════════

const CONTEXT_SERIALIZE_REGEX = /(?:JSON\.stringify|\.dump|serialize|\.toString)\s*\(.*(?:context|conversation|history|messages|chat_log|memory)/i;
const EXTERNAL_CALL_REGEX = /(?:fetch|axios|request|http\.|urllib|requests\.|tool_call|function_call|mcp|\.post\(|\.get\(|\.send\()/i;

export function traceContextFlow(
  lines: string[],
  serializeLineIndex: number,
  windowSize = 15
): string[] | undefined {
  const chain: string[] = [];

  // Record the serialization point
  chain.push(`serialize@L${serializeLineIndex + 1}: ${lines[serializeLineIndex].trim().substring(0, 80)}`);

  // Look forward for external calls
  const end = Math.min(lines.length, serializeLineIndex + windowSize + 1);
  for (let i = serializeLineIndex + 1; i < end; i++) {
    if (EXTERNAL_CALL_REGEX.test(lines[i])) {
      chain.push(`external_call@L${i + 1}: ${lines[i].trim().substring(0, 80)}`);
      return chain;
    }
  }

  // Look backward — maybe the serialized var was passed to a call above
  const start = Math.max(0, serializeLineIndex - windowSize);
  for (let i = serializeLineIndex - 1; i >= start; i--) {
    if (EXTERNAL_CALL_REGEX.test(lines[i])) {
      chain.push(`external_call@L${i + 1}: ${lines[i].trim().substring(0, 80)}`);
      return chain;
    }
  }

  return undefined;
}

// ═══════════════════════════════════════════════════════════
// Core Matching Engine
// ═══════════════════════════════════════════════════════════

function getContext(lines: string[], lineIndex: number, contextSize = 2): string {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length, lineIndex + contextSize + 1);
  return lines.slice(start, end).join('\n');
}

/**
 * Match a single pattern against content with full intelligence pipeline
 */
export function matchPattern(
  pattern: DetectionPattern,
  content: string,
  file: string
): Finding[] {
  if (!shouldApplyPattern(pattern, file)) return [];

  const findings: Finding[] = [];
  const lines = content.split('\n');
  const testFile = isTestFile(file);

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const matches = line.matchAll(new RegExp(pattern.pattern, 'gi'));

    for (const match of matches) {
      const originalSeverity = pattern.severity;
      const shouldDowngrade = testFile && (
        CREDENTIAL_CATEGORIES.has(pattern.category) ||
        INJECTION_CATEGORIES.has(pattern.category)
      );

      const finding: Finding = {
        pattern: shouldDowngrade
          ? { ...pattern, severity: SEVERITY_DOWNGRADE[originalSeverity] }
          : pattern,
        file,
        line: lineIndex + 1,
        column: (match.index || 0) + 1,
        match: match[0],
        context: getContext(lines, lineIndex),
        timestamp: new Date(),
        classification: 'unclassified',
        originalSeverity,
        severityDowngraded: shouldDowngrade,
        isTestFile: testFile,
      };

      // Taint proximity for dangerous sink patterns
      if (TAINT_SINK_PATTERNS.has(pattern.name)) {
        finding.taintProximity = analyzeTaintProximity(lines, lineIndex);

        // Escalate severity if tainted input is nearby
        if (finding.taintProximity === 'direct') {
          finding.pattern = { ...finding.pattern, severity: 'critical' };
        } else if (finding.taintProximity === 'nearby') {
          finding.pattern = { ...finding.pattern, severity: 'critical' };
        }
      }

      // Context flow tracing for context serialization patterns
      if (pattern.name === 'mcp_context_dump_to_tool') {
        finding.contextFlowChain = traceContextFlow(lines, lineIndex);
      }

      // Auto-classify
      finding.classification = classifyFinding(finding);

      findings.push(finding);
    }
  }

  return findings;
}

/**
 * Match multiple patterns against content
 */
export function matchPatterns(
  patterns: DetectionPattern[],
  content: string,
  file: string
): Finding[] {
  const findings: Finding[] = [];
  for (const pattern of patterns) {
    findings.push(...matchPattern(pattern, content, file));
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════
// Risk Scoring (uses downgraded severity, not original)
// ═══════════════════════════════════════════════════════════

export function calculateRiskScore(findings: Finding[]): RiskScore {
  const weights = { critical: 25, high: 10, medium: 3, low: 1 };
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let deductions = 0;

  for (const finding of findings) {
    const sev = finding.pattern.severity;
    counts[sev]++;
    deductions += weights[sev];
  }

  const total = Math.max(0, 100 - deductions);

  let level: RiskScore['level'];
  if (total >= 80) level = 'low';
  else if (total >= 60) level = 'moderate';
  else if (total >= 40) level = 'high';
  else level = 'critical';

  const owaspFindings = findings.filter((f) => f.pattern.owaspAsi);
  const owaspCompliance = owaspFindings.length === 0 ? 100 : Math.max(0, 100 - owaspFindings.length * 10);

  return { total, level, counts, owaspCompliance };
}

export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.pattern.name}:${f.file}:${f.line}:${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...findings].sort(
    (a, b) => severityOrder[a.pattern.severity] - severityOrder[b.pattern.severity]
  );
}

export function groupFindingsByFile(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.file) || [];
    existing.push(finding);
    groups.set(finding.file, existing);
  }
  return groups;
}

export function groupFindingsByCategory(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const category = finding.pattern.category;
    const existing = groups.get(category) || [];
    existing.push(finding);
    groups.set(category, existing);
  }
  return groups;
}

/**
 * Group findings by classification
 */
export function groupFindingsByClassification(findings: Finding[]): Map<FindingClassification, Finding[]> {
  const groups = new Map<FindingClassification, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.classification) || [];
    existing.push(finding);
    groups.set(finding.classification, existing);
  }
  return groups;
}

export function filterFindingsBySeverity(
  findings: Finding[],
  minSeverity: 'critical' | 'high' | 'medium' | 'low'
): Finding[] {
  const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
  const minLevel = severityOrder[minSeverity];
  return findings.filter((f) => severityOrder[f.pattern.severity] >= minLevel);
}

export function createScanResult(
  filesScanned: number,
  patternsChecked: number,
  findings: Finding[],
  startTime: number
): ScanResult {
  return {
    filesScanned,
    patternsChecked,
    findings: sortFindingsBySeverity(deduplicateFindings(findings)),
    riskScore: calculateRiskScore(findings),
    duration: Date.now() - startTime,
    timestamp: new Date(),
  };
}
