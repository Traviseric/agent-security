/**
 * Remote Code Execution (RCE) and Argument Injection Patterns
 *
 * Patterns for detecting command/argument injection attacks that can
 * escalate to remote code execution, particularly in AI agents with
 * command execution capabilities.
 *
 * Sources: THR-006 (Trail of Bits), FRM-002 (LangChain), ACAD-001
 */

import type { DetectionPattern } from './types.js';

/**
 * Argument Injection Patterns
 * Attacks that inject malicious flags into "safe" commands
 */
export const argumentInjectionPatterns: DetectionPattern[] = [
  {
    name: 'arg_inject_go_test',
    pattern: /go\s+test\s+.*-exec/i,
    severity: 'critical',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'Go test -exec flag injection (RCE)',
    example: 'go test -exec "bash -c whoami" ./...',
    remediation: 'Remove go test from allowlist or sandbox execution',
  },
  {
    name: 'arg_inject_git_format',
    pattern: /git\s+(?:show|log).*--format=%x/i,
    severity: 'critical',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'Git format hex encoding (payload injection)',
    example: 'git show --format=%x62%x61%x73%x68',
    remediation: 'Disallow --format flag in git commands',
  },
  {
    name: 'arg_inject_rg_pre',
    pattern: /rg\s+.*--pre\s+(?:bash|sh|python)/i,
    severity: 'critical',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'Ripgrep --pre flag with shell (RCE)',
    example: 'rg --pre bash "pattern" file',
    remediation: 'Disallow --pre flag in ripgrep commands',
  },
  {
    name: 'arg_inject_find_exec',
    pattern: /find\s+.*-exec/i,
    severity: 'high',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'Find -exec flag injection',
    example: 'find . -exec rm -rf {} \\;',
    remediation: 'Use find with -print only, or sandbox execution',
  },
  {
    name: 'arg_inject_tar_checkpoint',
    pattern: /tar\s+.*--checkpoint-action/i,
    severity: 'critical',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'Tar checkpoint-action (GTFOBINS RCE)',
    example: 'tar --checkpoint-action=exec=bash',
    remediation: 'Remove tar from allowlist or filter --checkpoint flags',
  },
  {
    name: 'arg_inject_fd_x',
    pattern: /fd\s+.*-x/i,
    severity: 'high',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'fd -x flag command execution',
    example: 'fd pattern -x rm {}',
    remediation: 'Disallow -x flag in fd commands',
  },
  {
    name: 'arg_inject_xargs',
    pattern: /xargs\s+.*-I/i,
    severity: 'high',
    category: 'argument_injection',
    source: 'THR-006',
    description: 'xargs -I flag command execution',
    example: 'echo "file" | xargs -I {} rm {}',
  },
];

/**
 * Missing Argument Separator Patterns
 * Code that doesn't properly separate user input from flags
 */
export const missingArgSeparatorPatterns: DetectionPattern[] = [
  {
    name: 'missing_arg_separator_template',
    pattern: /(?:exec|spawn|system|popen|run|shell)\s*\(.*\$\{?(?:USER_INPUT|QUERY|ARG|INPUT|PARAM)\}?(?!\s+--)/i,
    severity: 'high',
    category: 'argument_injection',
    source: 'THR-006',
    context: 'code',
    description: 'User input in shell command without argument separator (--)',
    example: 'exec(`cmd ${USER_INPUT}`) → exec(`cmd -- ${USER_INPUT}`)',
    remediation: 'Always use -- separator before user input in shell commands',
  },
  {
    name: 'flag_like_input',
    pattern: /^-[a-zA-Z]/,
    severity: 'high',
    category: 'argument_injection',
    source: 'THR-006',
    context: 'user_input',
    description: 'Flag-like user input (potential injection)',
    example: 'User input: -x=python3',
  },
];

/**
 * SSRF Patterns
 * Server-Side Request Forgery attacks
 */
export const ssrfPatterns: DetectionPattern[] = [
  {
    name: 'ssrf_localhost',
    pattern: /(?:fetch|request|get|post|put|curl|wget|axios|http\.get|urllib|requests\.)\s*\(?\s*["']?https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: 'high',
    category: 'ssrf',
    source: 'FRM-002',
    context: 'code',
    description: 'SSRF attempt to localhost via request call',
    example: 'fetch("http://localhost:8080/admin")',
    cve: 'CVE-2023-46229',
  },
  {
    name: 'ssrf_internal',
    pattern: /https?:\/\/(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/i,
    severity: 'critical',
    category: 'ssrf',
    source: 'FRM-002',
    description: 'SSRF attempt to internal network',
    example: 'http://192.168.1.1/admin',
    cve: 'CVE-2023-46229',
  },
  {
    name: 'ssrf_metadata',
    pattern: /https?:\/\/169\.254\.169\.254/i,
    severity: 'critical',
    category: 'ssrf',
    source: 'THR-005',
    description: 'SSRF to cloud metadata service',
    example: 'http://169.254.169.254/latest/meta-data/',
  },
];

/**
 * Code Injection Patterns
 * Direct code injection vulnerabilities
 */
export const codeInjectionPatterns: DetectionPattern[] = [
  {
    name: 'langchain_import_bypass',
    pattern: /__import__\s*\(/,
    severity: 'critical',
    category: 'code_injection',
    source: 'FRM-002',
    description: 'Dynamic import bypass (CVE-2023-44467)',
    example: "__import__('subprocess').run(['whoami'])",
    cve: 'CVE-2023-44467',
    remediation: 'Block __import__ in generated/executed code',
  },
  {
    name: 'dangerous_module_import',
    pattern: /(?:subprocess|os|sys|shutil|importlib)\s*\.\s*(?:run|system|exec|popen)/i,
    severity: 'high',
    category: 'code_injection',
    source: 'FRM-002',
    context: 'generated_code',
    description: 'Dangerous module call in generated code',
    example: 'subprocess.run(user_input)',
  },
  {
    name: 'eval_exec_usage',
    pattern: /(?:eval|exec)\s*\(/,
    severity: 'high',
    category: 'code_injection',
    source: 'ai-assistant',
    description: 'Eval/exec usage (code execution risk)',
    example: 'eval(user_input)',
    remediation: 'Never use eval/exec with untrusted input',
  },
  {
    name: 'pickle_loads',
    pattern: /pickle\.loads?\s*\(/,
    severity: 'high',
    category: 'code_injection',
    source: 'ai-assistant',
    description: 'Insecure deserialization via pickle',
    example: 'pickle.loads(user_data)',
    remediation: 'Use safe serialization formats like JSON',
  },
];

/**
 * LangChain-Specific Patterns
 */
export const langchainPatterns: DetectionPattern[] = [
  {
    name: 'langchain_sitemap_loader',
    pattern: /SitemapLoader\s*\(/,
    severity: 'medium',
    category: 'ssrf',
    source: 'FRM-002',
    description: 'SitemapLoader usage (verify domain allowlist)',
    example: 'SitemapLoader(web_path=user_input)',
    cve: 'CVE-2023-46229',
    remediation: 'Implement domain allowlist for SitemapLoader',
  },
  {
    name: 'langchain_palchain',
    pattern: /PALChain|PythonREPL/i,
    severity: 'high',
    category: 'code_injection',
    source: 'FRM-002',
    description: 'PALChain/PythonREPL usage (code execution risk)',
    example: 'PALChain.from_math_prompt(llm)',
    remediation: 'Sandbox any code execution, expand blocklists',
  },
];

/**
 * Dangerous Command Patterns
 * Destructive system commands
 */
export const dangerousCommandPatterns: DetectionPattern[] = [
  {
    name: 'rm_rf',
    pattern: /rm\s+(-[rf]+\s+)*-[rf]/i,
    severity: 'high',
    category: 'dangerous_commands',
    source: 'ai-assistant',
    description: 'Recursive/forced file deletion',
    example: 'rm -rf /',
  },
  {
    name: 'sql_drop',
    pattern: /DROP\s+(?:TABLE|DATABASE|SCHEMA)/i,
    severity: 'high',
    category: 'dangerous_commands',
    source: 'ai-assistant',
    description: 'SQL DROP statement',
    example: 'DROP TABLE users',
  },
  {
    name: 'chmod_dangerous',
    pattern: /chmod\s+(?:777|a\+rwx)/i,
    severity: 'medium',
    category: 'dangerous_commands',
    source: 'ai-assistant',
    description: 'Dangerous chmod permissions',
    example: 'chmod 777 /etc/passwd',
  },
  {
    name: 'shell_true',
    pattern: /shell\s*=\s*True/i,
    severity: 'high',
    category: 'code_injection',
    source: 'ai-assistant',
    context: 'code',
    description: 'subprocess with shell=True (injection risk)',
    example: 'subprocess.run(cmd, shell=True)',
    remediation: 'Use shell=False and pass command as list',
  },
];

/**
 * All RCE-related patterns combined
 */
export const allRcePatterns: DetectionPattern[] = [
  ...argumentInjectionPatterns,
  ...missingArgSeparatorPatterns,
  ...ssrfPatterns,
  ...codeInjectionPatterns,
  ...langchainPatterns,
  ...dangerousCommandPatterns,
];
