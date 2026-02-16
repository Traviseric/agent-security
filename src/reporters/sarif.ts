/**
 * SARIF Reporter
 *
 * Outputs scan results in SARIF 2.1.0 format for GitHub Code Scanning
 * and other SARIF-compatible tools.
 */

import type { Finding, ScanResult, Severity } from '../patterns/types.js';

const VERSION = '1.1.0';
const SCHEMA_URI = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const INFORMATION_URI = 'https://github.com/empowered-humanity/agent-security';

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
 * Build deduplicated SARIF rules from findings
 */
function buildRules(findings: Finding[]): SarifRule[] {
  const seen = new Map<string, SarifRule>();

  for (const finding of findings) {
    const id = finding.pattern.name;
    if (seen.has(id)) continue;

    const rule: SarifRule = {
      id,
      shortDescription: { text: finding.pattern.description },
      defaultConfiguration: {
        level: severityToLevel(finding.pattern.severity),
      },
    };

    if (finding.pattern.owaspAsi) {
      rule.properties = { owaspAsi: finding.pattern.owaspAsi };
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
