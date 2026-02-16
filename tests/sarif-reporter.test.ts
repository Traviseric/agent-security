/**
 * SARIF Reporter Tests
 */

import { describe, it, expect } from 'vitest';
import { formatAsSarif } from '../src/reporters/sarif.js';
import type { ScanResult, Finding, DetectionPattern } from '../src/patterns/types.js';

function makePattern(overrides: Partial<DetectionPattern> = {}): DetectionPattern {
  return {
    name: 'test-pattern',
    pattern: /test/,
    severity: 'high',
    category: 'code_injection',
    source: 'custom',
    description: 'Test pattern description',
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    pattern: makePattern(),
    file: 'src/app.ts',
    line: 10,
    column: 5,
    match: 'test match',
    context: 'const x = test match;',
    timestamp: new Date('2025-01-01'),
    classification: 'live_vulnerability',
    originalSeverity: 'high',
    severityDowngraded: false,
    isTestFile: false,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    filesScanned: 1,
    patternsChecked: 176,
    findings,
    riskScore: {
      total: 80,
      level: 'moderate',
      counts: { critical: 0, high: 0, medium: 0, low: 0 },
      owaspCompliance: 100,
    },
    duration: 150,
    timestamp: new Date('2025-01-01'),
  };
}

describe('SARIF Reporter', () => {
  it('returns valid JSON with $schema and version 2.1.0', () => {
    const result = makeScanResult();
    const output = formatAsSarif(result);
    const sarif = JSON.parse(output);

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('agent-security');
    expect(sarif.runs[0].tool.driver.semanticVersion).toBe('1.1.0');
  });

  it('maps critical/high to error, medium to warning, low to note', () => {
    const findings = [
      makeFinding({ pattern: makePattern({ severity: 'critical', name: 'p-critical' }) }),
      makeFinding({ pattern: makePattern({ severity: 'high', name: 'p-high' }) }),
      makeFinding({ pattern: makePattern({ severity: 'medium', name: 'p-medium' }) }),
      makeFinding({ pattern: makePattern({ severity: 'low', name: 'p-low' }) }),
    ];
    const result = makeScanResult(findings);
    const sarif = JSON.parse(formatAsSarif(result));

    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[1].level).toBe('error');
    expect(sarif.runs[0].results[2].level).toBe('warning');
    expect(sarif.runs[0].results[3].level).toBe('note');
  });

  it('creates one result per finding with deduplicated rules', () => {
    const pattern = makePattern({ name: 'duplicate-pattern' });
    const findings = [
      makeFinding({ pattern, file: 'a.ts', line: 1 }),
      makeFinding({ pattern, file: 'b.ts', line: 5 }),
    ];
    const result = makeScanResult(findings);
    const sarif = JSON.parse(formatAsSarif(result));

    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe('duplicate-pattern');
  });

  it('includes classification, taintProximity, owaspAsi in properties', () => {
    const finding = makeFinding({
      pattern: makePattern({ owaspAsi: 'ASI-01' }),
      classification: 'credential_exposure',
      taintProximity: 'direct',
      contextFlowChain: ['source', 'sink'],
    });
    const result = makeScanResult([finding]);
    const sarif = JSON.parse(formatAsSarif(result));
    const props = sarif.runs[0].results[0].properties;

    expect(props.classification).toBe('credential_exposure');
    expect(props.taintProximity).toBe('direct');
    expect(props.owaspAsi).toBe('ASI-01');
    expect(props.contextFlowChain).toEqual(['source', 'sink']);
  });

  it('produces zero results for empty findings', () => {
    const result = makeScanResult([]);
    const sarif = JSON.parse(formatAsSarif(result));

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('converts Windows backslash paths to forward slashes', () => {
    const finding = makeFinding({ file: 'C:\\Users\\dev\\project\\src\\app.ts' });
    const result = makeScanResult([finding]);
    const sarif = JSON.parse(formatAsSarif(result));
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    expect(uri).not.toContain('\\');
    expect(uri).toBe('C:/Users/dev/project/src/app.ts');
  });

  it('strips baseDir prefix to produce relative paths', () => {
    const finding = makeFinding({ file: 'C:\\Users\\dev\\project\\src\\app.ts' });
    const result = makeScanResult([finding]);
    const sarif = JSON.parse(formatAsSarif(result, 'C:\\Users\\dev\\project'));
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    expect(uri).toBe('src/app.ts');
  });
});
