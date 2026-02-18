/**
 * Console Reporter
 *
 * Formats scan results for terminal output with colors.
 * Includes intelligence layer data: classification, taint proximity, context flow.
 */

import chalk from 'chalk';
import type { Finding, FindingClassification, ScanResult, Severity } from '../patterns/types.js';
import {
  groupFindingsByFile,
  groupFindingsByCategory,
  groupFindingsByClassification,
} from '../scanner/engine.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🚨',
  high: '❌',
  medium: '⚠️',
  low: 'ℹ️',
};

const CLASSIFICATION_COLORS: Record<FindingClassification, (text: string) => string> = {
  test_payload: chalk.gray,
  live_vulnerability: chalk.red.bold,
  credential_exposure: chalk.yellow.bold,
  configuration_risk: chalk.yellow,
  architectural_weakness: chalk.magenta.bold,
  supply_chain_risk: chalk.cyan,
  unclassified: chalk.dim,
};

/**
 * Format a single finding for console output
 */
export function formatFinding(finding: Finding, showContext = false): string {
  const { pattern, file, line, column, match } = finding;
  const severityColor = SEVERITY_COLORS[pattern.severity];
  const icon = SEVERITY_ICONS[pattern.severity];
  const classColor = CLASSIFICATION_COLORS[finding.classification] || chalk.dim;

  let output = `${icon} ${severityColor(`[${pattern.severity.toUpperCase()}]`)} ${chalk.cyan(pattern.name)}`;
  output += ` ${classColor(`(${finding.classification})`)}\n`;
  output += `   ${chalk.gray('File:')} ${file}:${line}:${column}\n`;
  output += `   ${chalk.gray('Match:')} ${chalk.white(match.substring(0, 120))}\n`;
  output += `   ${chalk.gray('Description:')} ${pattern.description}\n`;

  if (finding.severityDowngraded) {
    output += `   ${chalk.gray('Downgraded:')} ${finding.originalSeverity} → ${pattern.severity} (test file)\n`;
  }

  if (finding.taintProximity) {
    const taintColor = finding.taintProximity === 'direct' || finding.taintProximity === 'nearby'
      ? chalk.red.bold : chalk.gray;
    output += `   ${chalk.gray('Taint:')} ${taintColor(finding.taintProximity)}\n`;
  }

  if (finding.contextFlowChain && finding.contextFlowChain.length > 0) {
    output += `   ${chalk.gray('Flow chain:')}\n`;
    for (const step of finding.contextFlowChain) {
      output += `     ${chalk.magenta('→')} ${step}\n`;
    }
  }

  if (pattern.owaspAsi) {
    output += `   ${chalk.gray('OWASP ASI:')} ${chalk.magenta(pattern.owaspAsi)}\n`;
  }

  if (pattern.cve) {
    output += `   ${chalk.gray('CVE:')} ${chalk.red(pattern.cve)}\n`;
  }

  if (pattern.remediation) {
    output += `   ${chalk.gray('Remediation:')} ${chalk.green(pattern.remediation)}\n`;
  }

  if (showContext && finding.context) {
    output += `   ${chalk.gray('Context:')}\n`;
    const lines = finding.context.split('\n');
    for (const contextLine of lines) {
      output += `   ${chalk.dim('│')} ${contextLine}\n`;
    }
  }

  return output;
}

/**
 * Format the risk score for console output
 */
export function formatRiskScore(result: ScanResult): string {
  const { riskScore } = result;
  let levelColor: (text: string) => string;

  switch (riskScore.level) {
    case 'critical':
      levelColor = chalk.bgRed.white.bold;
      break;
    case 'high':
      levelColor = chalk.red.bold;
      break;
    case 'moderate':
      levelColor = chalk.yellow.bold;
      break;
    case 'low':
      levelColor = chalk.green.bold;
      break;
  }

  let output = chalk.bold('\n📊 Risk Assessment\n');
  output += `${chalk.gray('═'.repeat(40))}\n`;
  output += `Risk Score: ${levelColor(`${riskScore.total}/100`)} (${levelColor(riskScore.level.toUpperCase())})\n`;
  output += `OWASP Compliance: ${(riskScore.owaspCompliance >= 80 ? chalk.green : chalk.red)(`${riskScore.owaspCompliance}%`)}\n\n`;

  output += chalk.bold('Findings by Severity:\n');
  output += `  ${SEVERITY_ICONS.critical} Critical: ${chalk.red.bold(riskScore.counts.critical.toString())}\n`;
  output += `  ${SEVERITY_ICONS.high} High: ${chalk.red(riskScore.counts.high.toString())}\n`;
  output += `  ${SEVERITY_ICONS.medium} Medium: ${chalk.yellow(riskScore.counts.medium.toString())}\n`;
  output += `  ${SEVERITY_ICONS.low} Low: ${chalk.blue(riskScore.counts.low.toString())}\n`;

  return output;
}

/**
 * Format intelligence summary for console output
 */
export function formatIntelligenceSummary(findings: Finding[]): string {
  let output = chalk.bold('\n🧠 Intelligence Summary\n');
  output += `${chalk.gray('═'.repeat(40))}\n\n`;

  // Classification breakdown
  const byClass = groupFindingsByClassification(findings);
  output += chalk.bold('By Classification:\n');
  const classOrder: FindingClassification[] = [
    'live_vulnerability', 'credential_exposure', 'test_payload',
    'supply_chain_risk', 'architectural_weakness', 'configuration_risk', 'unclassified',
  ];
  for (const cls of classOrder) {
    const items = byClass.get(cls);
    if (items && items.length > 0) {
      const pct = ((items.length / findings.length) * 100).toFixed(1);
      const color = CLASSIFICATION_COLORS[cls] || chalk.dim;
      output += `  ${color(cls.padEnd(25))} ${String(items.length).padStart(5)}  (${pct}%)\n`;
    }
  }

  // Taint proximity
  const tainted = findings.filter(f => f.taintProximity);
  if (tainted.length > 0) {
    const direct = tainted.filter(f => f.taintProximity === 'direct').length;
    const nearby = tainted.filter(f => f.taintProximity === 'nearby').length;
    const distant = tainted.filter(f => f.taintProximity === 'distant').length;

    output += chalk.bold('\nTaint Proximity:\n');
    output += `  ${(direct > 0 ? chalk.red.bold : chalk.gray)(`Direct (same line):  ${direct}`)}\n`;
    output += `  ${(nearby > 0 ? chalk.red.bold : chalk.gray)(`Nearby (10 lines):   ${nearby}`)}\n`;
    output += `  ${chalk.gray(`Distant (no input):  ${distant}`)}\n`;
  }

  // Severity downgrades
  const downgraded = findings.filter(f => f.severityDowngraded);
  if (downgraded.length > 0) {
    output += chalk.bold('\nTest File Downgrades:\n');
    output += `  ${chalk.cyan(downgraded.length.toString())} findings severity-downgraded (test/fixture/example files)\n`;
  }

  // Context flow chains
  const flowChains = findings.filter(f => f.contextFlowChain && f.contextFlowChain.length > 0);
  if (flowChains.length > 0) {
    output += chalk.bold('\nContext Flow Chains:\n');
    output += `  ${chalk.magenta(flowChains.length.toString())} serialization → external call chains detected\n`;
  }

  // Test vs Production split
  const testCount = findings.filter(f => f.isTestFile).length;
  const prodCount = findings.length - testCount;
  output += chalk.bold('\nTest vs Production:\n');
  output += `  Test files:       ${chalk.gray(testCount.toString())} findings\n`;
  output += `  Production files: ${chalk.cyan(prodCount.toString())} findings\n`;

  return output;
}

/**
 * Format the full scan result for console output
 */
export function formatScanResult(result: ScanResult, options: {
  showContext?: boolean;
  groupBy?: 'file' | 'category' | 'severity' | 'classification';
  verbose?: boolean;
} = {}): string {
  const { showContext = false, groupBy = 'severity', verbose = false } = options;

  let output = '';

  // Header
  output += chalk.bold.cyan('\n🔍 Agent Security Scan Results\n');
  output += chalk.gray('═'.repeat(50)) + '\n\n';

  // Summary
  output += `Files scanned: ${chalk.cyan(result.filesScanned.toString())}\n`;
  output += `Patterns checked: ${chalk.cyan(result.patternsChecked.toString())}\n`;
  output += `Duration: ${chalk.cyan(`${result.duration}ms`)}\n`;
  output += `Total findings: ${chalk.cyan(result.findings.length.toString())}\n\n`;

  if (result.findings.length === 0) {
    output += chalk.green.bold('✅ No security issues found!\n');
    return output;
  }

  // Intelligence summary (always shown)
  output += formatIntelligenceSummary(result.findings);

  // Findings
  output += chalk.bold('\n📋 Findings\n');
  output += chalk.gray('─'.repeat(40)) + '\n\n';

  if (groupBy === 'file') {
    const byFile = groupFindingsByFile(result.findings);
    for (const [file, findings] of byFile) {
      output += chalk.bold.underline(`\n${file}\n`);
      for (const finding of findings) {
        output += formatFinding(finding, showContext) + '\n';
      }
    }
  } else if (groupBy === 'category') {
    const byCategory = groupFindingsByCategory(result.findings);
    for (const [category, findings] of byCategory) {
      output += chalk.bold.underline(`\n${category} (${findings.length})\n`);
      for (const finding of findings) {
        output += formatFinding(finding, showContext) + '\n';
      }
    }
  } else if (groupBy === 'classification') {
    const byClass = groupFindingsByClassification(result.findings);
    const classOrder: FindingClassification[] = [
      'live_vulnerability', 'credential_exposure', 'architectural_weakness',
      'supply_chain_risk', 'configuration_risk', 'test_payload', 'unclassified',
    ];
    for (const cls of classOrder) {
      const findings = byClass.get(cls);
      if (findings && findings.length > 0) {
        const color = CLASSIFICATION_COLORS[cls] || chalk.dim;
        output += chalk.bold(`\n${color(cls.toUpperCase())} (${findings.length})\n`);
        for (const finding of findings) {
          output += formatFinding(finding, showContext) + '\n';
        }
      }
    }
  } else {
    // Group by severity (default)
    for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
      const findings = result.findings.filter((f) => f.pattern.severity === severity);
      if (findings.length > 0) {
        output += chalk.bold(`\n${SEVERITY_COLORS[severity](severity.toUpperCase())} (${findings.length})\n`);
        for (const finding of findings) {
          output += formatFinding(finding, showContext) + '\n';
        }
      }
    }
  }

  // Risk score
  output += formatRiskScore(result);

  // Recommendations
  if (result.riskScore.level === 'critical' || result.riskScore.level === 'high') {
    output += chalk.bold.red('\n⚠️  Action Required\n');
    output += chalk.red('This codebase has significant security vulnerabilities.\n');
    output += chalk.red('Address critical and high severity findings before deployment.\n');
  }

  return output;
}

/**
 * Print scan result to console
 */
export function printScanResult(result: ScanResult, options: {
  showContext?: boolean;
  groupBy?: 'file' | 'category' | 'severity' | 'classification';
  verbose?: boolean;
} = {}): void {
  console.log(formatScanResult(result, options));
}
