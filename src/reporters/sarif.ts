/**
 * SARIF Reporter
 *
 * Outputs scan results in SARIF 2.1.0 format for GitHub Code Scanning
 * and other SARIF-compatible tools.
 *
 * Features:
 * - CWE ID mappings for all attack categories
 * - OWASP ASI tags on rules
 * - GitHub Security tab integration
 */

import type { AttackCategory, Finding, ScanResult, Severity } from '../patterns/types.js';

const VERSION = '1.2.0';
const SCHEMA_URI = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const INFORMATION_URI = 'https://github.com/empowered-humanity/agent-security';

/**
 * Map attack categories to CWE IDs.
 * Uses the most specific applicable CWE for each category.
 */
const CATEGORY_CWE_MAP: Partial<Record<AttackCategory, string>> = {
  instruction_override: 'CWE-74',    // Injection
  role_manipulation: 'CWE-284',      // Improper Access Control
  boundary_escape: 'CWE-116',        // Improper Encoding or Escaping
  data_exfiltration: 'CWE-200',      // Information Exposure
  hidden_injection: 'CWE-94',        // Code Injection
  stealth_instruction: 'CWE-94',
  url_reconstruction: 'CWE-601',     // Open Redirect
  credential_theft: 'CWE-522',       // Insufficiently Protected Credentials
  credential_exposure: 'CWE-798',    // Hardcoded Credentials
  cross_agent_escalation: 'CWE-269', // Improper Privilege Management
  mcp_attack: 'CWE-346',            // Origin Validation Error
  rag_poisoning: 'CWE-94',
  persistence: 'CWE-506',           // Embedded Malicious Code
  goal_hijacking: 'CWE-74',
  session_smuggling: 'CWE-384',     // Session Fixation
  argument_injection: 'CWE-88',     // Argument Injection
  code_injection: 'CWE-94',
  ssrf: 'CWE-918',                  // SSRF
  reconnaissance: 'CWE-200',
  prompt_extraction: 'CWE-200',
  defense_evasion: 'CWE-693',       // Protection Mechanism Failure
  hierarchy_violation: 'CWE-269',
  adversarial_suffix: 'CWE-74',
  ASI01_goal_hijack: 'CWE-74',
  ASI02_tool_misuse: 'CWE-269',
  ASI03_privilege_abuse: 'CWE-269',
  ASI04_supply_chain: 'CWE-494',    // Download Without Integrity Check
  ASI05_rce: 'CWE-94',
  ASI06_memory_poisoning: 'CWE-471', // Modification of Assumed-Immutable Data
  ASI07_insecure_comms: 'CWE-319',  // Cleartext Transmission
  ASI08_cascading_failures: 'CWE-400', // Uncontrolled Resource Consumption
  ASI09_trust_exploitation: 'CWE-290', // Auth Bypass by Spoofing
  ASI10_rogue_agents: 'CWE-506',
  config_vulnerability: 'CWE-16',   // Configuration
  permission_escalation: 'CWE-269',
  behavior_manipulation: 'CWE-74',
  platform_specific: 'CWE-74',
  rendering_exfil: 'CWE-200',
  path_traversal: 'CWE-22',
  dangerous_commands: 'CWE-78',     // OS Command Injection
};

interface SarifMessage {
  text: string;
}

interface SarifRegion {
  startLine: number;
  startColumn?: number;
}

interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region: SarifRegion;
}

interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: SarifMessage;
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  shortDescription: SarifMessage;
  fullDescription?: SarifMessage;
  helpUri?: string;
  defaultConfiguration?: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
  properties?: Record<string, unknown>;
}

interface SarifToolDriver {
  name: string;
  semanticVersion: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRun {
  tool: {
    driver: SarifToolDriver;
  };
  results: SarifResult[];
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

/**
 * Map scanner severity to SARIF level
 */
function severityToLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
  }
}

/**
 * Normalize a file path to a forward-slash relative URI.
 * Strips the baseDir prefix if provided, and converts backslashes to forward slashes.
 */
function normalizeUri(filePath: string, baseDir?: string): string {
  let uri = filePath;
  if (baseDir) {
    const normalizedBase = baseDir.replace(/\\/g, '/').replace(/\/$/, '') + '/';
    const normalizedPath = uri.replace(/\\/g, '/');
    if (normalizedPath.startsWith(normalizedBase)) {
      uri = normalizedPath.slice(normalizedBase.length);
    } else {
      uri = normalizedPath;
    }
  }
  return uri.replace(/\\/g, '/');
}

/**
 * Get the CWE ID for a finding, checking pattern.cwe first then category mapping
 */
function getCweId(finding: Finding): string | undefined {
  if (finding.pattern.cve) return undefined; // cve is separate
  return CATEGORY_CWE_MAP[finding.pattern.category];
}

/**
 * Build deduplicated SARIF rules from findings
 */
function buildRules(findings: Finding[]): SarifRule[] {
  const seen = new Map<string, SarifRule>();

  for (const finding of findings) {
    const id = finding.pattern.name;
    if (seen.has(id)) continue;

    const cweId = getCweId(finding);
    const tags: string[] = [];
    if (cweId) tags.push(cweId);
    if (finding.pattern.owaspAsi) tags.push(`OWASP-${finding.pattern.owaspAsi}`);
    tags.push(`security`);

    const rule: SarifRule = {
      id,
      shortDescription: { text: finding.pattern.description },
      defaultConfiguration: {
        level: severityToLevel(finding.pattern.severity),
      },
      properties: {
        tags,
        ...(finding.pattern.owaspAsi && { owaspAsi: finding.pattern.owaspAsi }),
        ...(cweId && { cweId }),
      },
    };

    if (cweId) {
      const cweNum = cweId.replace('CWE-', '');
      rule.helpUri = `https://cwe.mitre.org/data/definitions/${cweNum}.html`;
    }

    if (finding.pattern.remediation) {
      rule.fullDescription = { text: finding.pattern.remediation };
    }

    seen.set(id, rule);
  }

  return Array.from(seen.values());
}

/**
 * Build a SARIF result from a finding
 */
function buildResult(finding: Finding, baseDir?: string): SarifResult {
  const result: SarifResult = {
    ruleId: finding.pattern.name,
    level: severityToLevel(finding.pattern.severity),
    message: { text: finding.pattern.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: normalizeUri(finding.file, baseDir),
          },
          region: {
            startLine: finding.line,
            startColumn: finding.column,
          },
        },
      },
    ],
  };

  const properties: Record<string, unknown> = {};
  if (finding.classification) properties.classification = finding.classification;
  if (finding.taintProximity) properties.taintProximity = finding.taintProximity;
  if (finding.pattern.owaspAsi) properties.owaspAsi = finding.pattern.owaspAsi;
  if (finding.contextFlowChain && finding.contextFlowChain.length > 0) {
    properties.contextFlowChain = finding.contextFlowChain;
  }

  if (Object.keys(properties).length > 0) {
    result.properties = properties;
  }

  return result;
}

/**
 * Format scan result as SARIF 2.1.0 JSON string
 */
export function formatAsSarif(result: ScanResult, baseDir?: string): string {
  const sarifLog: SarifLog = {
    $schema: SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'agent-security',
            semanticVersion: VERSION,
            informationUri: INFORMATION_URI,
            rules: buildRules(result.findings),
          },
        },
        results: result.findings.map((f) => buildResult(f, baseDir)),
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}
