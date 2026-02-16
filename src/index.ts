#!/usr/bin/env node
/**
 * Agent Security Scanner CLI
 *
 * Security auditing tool for AI agent architectures.
 *
 * Usage:
 *   te-agent-security scan <path>        - Scan directory for vulnerabilities
 *   te-agent-security scan -f <file>     - Scan single file
 *   te-agent-security patterns           - List available patterns
 *   te-agent-security stats              - Show pattern statistics
 */

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import { resolve } from 'path';

import { scanDirectory, scanFile, scanContent } from './scanner/index.js';
import { printScanResult, formatScanResult } from './reporters/console.js';
import { formatAsJson } from './reporters/json.js';
import { formatAsSarif } from './reporters/sarif.js';
import { ALL_PATTERNS, getPatternStats, getPatternsByCategory, getPatternsByOwaspAsi, getPatternsMinSeverity } from './patterns/index.js';
import type { Severity, DetectionPattern } from './patterns/types.js';

const VERSION = '1.2.0';

program
  .name('te-agent-security')
  .description('Security scanner for AI agent architectures')
  .version(VERSION);

// Scan command
program
  .command('scan [path]')
  .description('Scan directory or file for security vulnerabilities')
  .option('-f, --file <file>', 'Scan a single file')
  .option('-s, --severity <level>', 'Minimum severity (critical, high, medium, low)', 'medium')
  .option('-o, --output <file>', 'Output file path')
  .option('--format <format>', 'Output format (console, json, sarif)', 'console')
  .option('--fail-on <severity>', 'Exit with code 1 if findings at or above severity (critical, high, medium, low)')
  .option('--context', 'Show code context for findings')
  .option('--group <by>', 'Group findings by (severity, file, category, classification)', 'severity')
  .option('--asi <id>', 'Filter by OWASP ASI category (e.g., ASI01, ASI06)')
  .option('-v, --verbose', 'Verbose output')
  .option('-q, --quiet', 'Quiet mode - only show errors')
  .action(async (path, options) => {
    const targetPath = options.file || path || process.cwd();
    const resolvedPath = resolve(targetPath);

    // Build filtered pattern set if --asi is specified
    let filteredPatterns: DetectionPattern[] | undefined;
    if (options.asi) {
      const asiId = options.asi.toUpperCase();
      filteredPatterns = getPatternsByOwaspAsi(asiId);
      if (filteredPatterns.length === 0) {
        console.error(chalk.red(`No patterns found for ASI category: ${asiId}`));
        console.error(chalk.gray('Valid categories: ASI01-ASI10'));
        process.exit(1);
      }
      if (options.severity && options.severity !== 'medium') {
        const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
        const minIndex = severityOrder.indexOf(options.severity as Severity);
        filteredPatterns = filteredPatterns.filter(
          (p) => severityOrder.indexOf(p.severity) >= minIndex
        );
      }
    }

    const scanOptions = filteredPatterns
      ? { patterns: filteredPatterns }
      : { minSeverity: options.severity as Severity };

    const spinner = options.quiet ? null : ora(
      filteredPatterns
        ? `Scanning for ${options.asi.toUpperCase()} patterns (${filteredPatterns.length} rules)...`
        : 'Scanning for security issues...'
    ).start();

    try {
      const result = options.file
        ? await (async () => {
            const findings = await scanFile(resolvedPath, scanOptions);
            const criticalCount = findings.filter((f) => f.pattern.severity === 'critical').length;
            const highCount = findings.filter((f) => f.pattern.severity === 'high').length;
            const mediumCount = findings.filter((f) => f.pattern.severity === 'medium').length;
            const lowCount = findings.filter((f) => f.pattern.severity === 'low').length;

            const level: 'critical' | 'high' | 'moderate' | 'low' =
              criticalCount > 0 ? 'critical' : findings.length > 5 ? 'high' : findings.length > 0 ? 'moderate' : 'low';

            return {
              filesScanned: 1,
              patternsChecked: filteredPatterns?.length ?? ALL_PATTERNS.length,
              findings,
              riskScore: {
                total: 100 - findings.length * 10,
                level,
                counts: {
                  critical: criticalCount,
                  high: highCount,
                  medium: mediumCount,
                  low: lowCount,
                },
                owaspCompliance: 100,
              },
              duration: 0,
              timestamp: new Date(),
            };
          })()
        : await scanDirectory(resolvedPath, scanOptions);

      spinner?.stop();

      // Format output
      if (options.format === 'json') {
        const jsonOutput = formatAsJson(result);
        if (options.output) {
          await writeFile(options.output, jsonOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(jsonOutput);
        }
      } else if (options.format === 'sarif') {
        const sarifOutput = formatAsSarif(result);
        if (options.output) {
          await writeFile(options.output, sarifOutput);
          console.log(chalk.green(`SARIF results written to ${options.output}`));
        } else {
          console.log(sarifOutput);
        }
      } else {
        const consoleOutput = formatScanResult(result, {
          showContext: options.context,
          groupBy: options.group,
          verbose: options.verbose,
        });

        if (options.output) {
          // Strip ANSI codes for file output
          const plainOutput = consoleOutput.replace(/\x1B\[[0-9;]*[mK]/g, '');
          await writeFile(options.output, plainOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(consoleOutput);
        }
      }

      // Exit with error code based on --fail-on threshold (default: critical)
      const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
      const failOn = options.failOn as Severity | undefined;
      const threshold = failOn && severityOrder.includes(failOn) ? failOn : 'critical';
      const thresholdIndex = severityOrder.indexOf(threshold);
      const hasFailures = severityOrder.slice(thresholdIndex).some(
        (sev) => result.riskScore.counts[sev] > 0
      );
      if (hasFailures) {
        process.exit(1);
      }
    } catch (error) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : error}`));
      process.exit(1);
    }
  });

// Patterns command
program
  .command('patterns')
  .description('List available detection patterns')
  .option('-c, --category <category>', 'Filter by category')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('--asi <id>', 'Filter by OWASP ASI category (e.g., ASI01, ASI06)')
  .option('--json', 'Output as JSON')
  .action((options) => {
    let patterns: DetectionPattern[] = ALL_PATTERNS;

    if (options.category) {
      patterns = getPatternsByCategory(options.category);
    }

    if (options.asi) {
      const asiId = options.asi.toUpperCase();
      patterns = patterns.filter((p) => p.owaspAsi === asiId);
    }

    if (options.severity) {
      patterns = patterns.filter((p) => p.severity === options.severity);
    }

    if (options.json) {
      console.log(
        JSON.stringify(
          patterns.map((p) => ({
            name: p.name,
            severity: p.severity,
            category: p.category,
            owaspAsi: p.owaspAsi || null,
            description: p.description,
            source: p.source,
          })),
          null,
          2
        )
      );
      return;
    }

    console.log(chalk.bold.cyan('\n📚 Detection Patterns\n'));
    console.log(chalk.gray('─'.repeat(60)));

    for (const pattern of patterns) {
      const severityColor =
        pattern.severity === 'critical'
          ? chalk.red
          : pattern.severity === 'high'
            ? chalk.yellow
            : pattern.severity === 'medium'
              ? chalk.blue
              : chalk.gray;

      console.log(`\n${chalk.bold(pattern.name)}`);
      console.log(`  Severity: ${severityColor(pattern.severity)}`);
      console.log(`  Category: ${chalk.cyan(pattern.category)}`);
      if (pattern.owaspAsi) {
        console.log(`  OWASP ASI: ${chalk.magenta(pattern.owaspAsi)}`);
      }
      console.log(`  Source: ${chalk.gray(pattern.source)}`);
      console.log(`  ${pattern.description}`);
      if (pattern.example) {
        console.log(`  Example: ${chalk.dim(pattern.example)}`);
      }
    }

    console.log(`\n${chalk.gray('─'.repeat(60))}`);
    console.log(`Total: ${patterns.length} patterns\n`);
  });

// Stats command
program
  .command('stats')
  .description('Show pattern library statistics')
  .option('--json', 'Output as JSON')
  .action((options) => {
    const stats = getPatternStats();

    if (options.json) {
      console.log(JSON.stringify(stats, null, 2));
      return;
    }

    console.log(chalk.bold.cyan('\n📊 Pattern Library Statistics\n'));
    console.log(chalk.gray('═'.repeat(40)));

    console.log(`\n${chalk.bold('Total Patterns:')} ${chalk.cyan(stats.total)}\n`);

    console.log(chalk.bold('By Severity:'));
    console.log(`  Critical: ${chalk.red(stats.bySeverity.critical)}`);
    console.log(`  High: ${chalk.yellow(stats.bySeverity.high)}`);
    console.log(`  Medium: ${chalk.blue(stats.bySeverity.medium)}`);
    console.log(`  Low: ${chalk.gray(stats.bySeverity.low)}`);

    console.log(chalk.bold('\nBy OWASP ASI:'));
    const asiLabels: Record<string, string> = {
      ASI01: 'Agent Goal Hijack',
      ASI02: 'Tool Misuse',
      ASI03: 'Privilege Abuse',
      ASI04: 'Supply Chain',
      ASI05: 'Code Execution',
      ASI06: 'Memory Poisoning',
      ASI07: 'Insecure Comms',
      ASI08: 'Cascading Failures',
      ASI09: 'Trust Exploitation',
      ASI10: 'Rogue Agents',
    };
    const asiIds = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05', 'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10'];
    let asiTotal = 0;
    for (const asiId of asiIds) {
      const count = stats.byOwaspAsi[asiId] || 0;
      asiTotal += count;
      const bar = '\u2588'.repeat(Math.min(count, 20));
      console.log(`  ${asiId} ${chalk.gray(asiLabels[asiId]?.padEnd(20) ?? '')}: ${chalk.cyan(String(count).padStart(3))} ${chalk.green(bar)}`);
    }
    console.log(`  ${chalk.gray('ASI-tagged total')}: ${chalk.cyan(asiTotal)}/${stats.total}`);

    console.log(chalk.bold('\nBy Category:'));
    const categories = Object.entries(stats.byCategory).sort((a, b) => b[1] - a[1]);
    for (const [category, count] of categories) {
      console.log(`  ${category}: ${chalk.cyan(count)}`);
    }

    console.log();
  });

// Version info
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(chalk.bold.cyan('\n🔒 Agent Security Scanner'));
    console.log(`Version: ${VERSION}`);
    console.log(`Patterns: ${ALL_PATTERNS.length}`);
    console.log(`Node: ${process.version}`);
    console.log();
  });

program.parse();
