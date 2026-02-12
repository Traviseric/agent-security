/**
 * Intelligence Layer Validation Script
 *
 * Scans key repos and validates all 4 intelligence layers:
 * 1. Test file severity downgrade
 * 2. Auto-classification
 * 3. Taint proximity analysis
 * 4. Context flow tracing
 */

import { scanDirectory } from './src/scanner/content-scanner.js';
import { groupFindingsByClassification } from './src/scanner/engine.js';
import type { Finding, FindingClassification, TaintProximity } from './src/patterns/types.js';

const REPOS_BASE = 'C:/code/learning-repos';

const REPOS_TO_SCAN = [
  'promptfoo',
  'garak',
  'PyRIT',
  'cleverhans',
  'PentestGPT',
];

function line(char = '─', len = 70) {
  return char.repeat(len);
}

function classificationSummary(findings: Finding[]) {
  const groups = groupFindingsByClassification(findings);
  const result: Record<string, number> = {};
  for (const [classification, items] of groups) {
    result[classification] = items.length;
  }
  return result;
}

function taintSummary(findings: Finding[]) {
  const tainted = findings.filter(f => f.taintProximity);
  const counts: Record<TaintProximity, number> = {
    direct: 0,
    nearby: 0,
    distant: 0,
    unknown: 0,
  };
  for (const f of tainted) {
    if (f.taintProximity) counts[f.taintProximity]++;
  }
  return { total: tainted.length, counts };
}

function severityDowngradeSummary(findings: Finding[]) {
  const downgraded = findings.filter(f => f.severityDowngraded);
  const examples = downgraded.slice(0, 3).map(f => ({
    pattern: f.pattern.name,
    file: f.file.split('/').slice(-2).join('/'),
    original: f.originalSeverity,
    downgraded: f.pattern.severity,
  }));
  return { count: downgraded.length, examples };
}

function contextFlowSummary(findings: Finding[]) {
  const withChain = findings.filter(f => f.contextFlowChain && f.contextFlowChain.length > 0);
  return {
    count: withChain.length,
    chains: withChain.slice(0, 5).map(f => ({
      file: f.file.split('/').slice(-2).join('/'),
      line: f.line,
      chain: f.contextFlowChain,
    })),
  };
}

async function main() {
  console.log('\n' + '═'.repeat(70));
  console.log('  AGENT SECURITY SCANNER — Intelligence Layer Validation');
  console.log('═'.repeat(70) + '\n');

  let totalFindings = 0;
  const allFindings: Finding[] = [];

  for (const repo of REPOS_TO_SCAN) {
    const repoPath = `${REPOS_BASE}/${repo}`;
    console.log(`\nScanning: ${repo}`);
    console.log(line());

    try {
      const result = await scanDirectory(repoPath, { minSeverity: 'low' });
      totalFindings += result.findings.length;
      allFindings.push(...result.findings);

      console.log(`  Files: ${result.filesScanned} | Findings: ${result.findings.length} | Duration: ${result.duration}ms`);

      // Layer 1: Classifications
      const cls = classificationSummary(result.findings);
      console.log(`\n  [CLASSIFICATION]`);
      for (const [key, count] of Object.entries(cls).sort((a, b) => b[1] - a[1])) {
        console.log(`    ${key}: ${count}`);
      }

      // Layer 2: Severity downgrades
      const downgrades = severityDowngradeSummary(result.findings);
      console.log(`\n  [SEVERITY DOWNGRADES] ${downgrades.count} findings downgraded`);
      for (const ex of downgrades.examples) {
        console.log(`    ${ex.pattern} in ${ex.file}: ${ex.original} → ${ex.downgraded}`);
      }

      // Layer 3: Taint proximity
      const taint = taintSummary(result.findings);
      if (taint.total > 0) {
        console.log(`\n  [TAINT PROXIMITY] ${taint.total} sink patterns analyzed`);
        console.log(`    Direct (user input on same line): ${taint.counts.direct}`);
        console.log(`    Nearby (within 10 lines): ${taint.counts.nearby}`);
        console.log(`    Distant (no nearby input): ${taint.counts.distant}`);
      }

      // Layer 4: Context flow traces
      const flow = contextFlowSummary(result.findings);
      if (flow.count > 0) {
        console.log(`\n  [CONTEXT FLOW] ${flow.count} serialization→external chains found`);
        for (const chain of flow.chains) {
          console.log(`    ${chain.file}:${chain.line}`);
          for (const step of chain.chain || []) {
            console.log(`      → ${step}`);
          }
        }
      }

      console.log('');

    } catch (err) {
      console.log(`  ERROR: ${err instanceof Error ? err.message : err}`);
    }
  }

  // Global summary
  console.log('\n' + '═'.repeat(70));
  console.log('  GLOBAL SUMMARY');
  console.log('═'.repeat(70));
  console.log(`\n  Total repos scanned: ${REPOS_TO_SCAN.length}`);
  console.log(`  Total findings: ${totalFindings}`);

  const globalCls = classificationSummary(allFindings);
  console.log(`\n  [CLASSIFICATION BREAKDOWN]`);
  for (const [key, count] of Object.entries(globalCls).sort((a, b) => b[1] - a[1])) {
    const pct = ((count / totalFindings) * 100).toFixed(1);
    console.log(`    ${key.padEnd(25)} ${String(count).padStart(5)}  (${pct}%)`);
  }

  const globalTaint = taintSummary(allFindings);
  console.log(`\n  [TAINT PROXIMITY]`);
  console.log(`    Total sink patterns: ${globalTaint.total}`);
  console.log(`    CRITICAL (direct):   ${globalTaint.counts.direct}`);
  console.log(`    CRITICAL (nearby):   ${globalTaint.counts.nearby}`);
  console.log(`    Lower risk (distant): ${globalTaint.counts.distant}`);

  const globalDowngrades = severityDowngradeSummary(allFindings);
  console.log(`\n  [SEVERITY DOWNGRADES] ${globalDowngrades.count} test file findings downgraded`);

  const globalFlow = contextFlowSummary(allFindings);
  console.log(`\n  [CONTEXT FLOW CHAINS] ${globalFlow.count} serialization→external chains`);

  // Test file vs production split
  const testFindings = allFindings.filter(f => f.isTestFile);
  const prodFindings = allFindings.filter(f => !f.isTestFile);
  console.log(`\n  [TEST vs PRODUCTION]`);
  console.log(`    Test files:       ${testFindings.length} findings`);
  console.log(`    Production files: ${prodFindings.length} findings`);

  console.log('\n' + '═'.repeat(70) + '\n');
}

main().catch(console.error);
