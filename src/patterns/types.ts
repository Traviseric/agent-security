/**
 * Agent Security Pattern Types
 *
 * Defines the core interfaces for detection patterns used throughout
 * the agent-security scanner.
 */

/**
 * Severity levels for security findings
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Finding classification — WHY this finding exists
 */
export type FindingClassification =
  | 'test_payload'           // Intentional attack payload in test/security tool
  | 'live_vulnerability'     // Real exploitable vulnerability in production code
  | 'credential_exposure'    // Hardcoded or leaked credential
  | 'configuration_risk'     // Insecure configuration setting
  | 'architectural_weakness' // Structural design flaw in agent architecture
  | 'supply_chain_risk'      // Dependency or package integrity concern
  | 'unclassified';          // Default — not yet classified

/**
 * Taint proximity — how close a dangerous sink is to untrusted input
 */
export type TaintProximity =
  | 'direct'    // User input flows directly into sink (same line or assignment)
  | 'nearby'    // User input source is within 10 lines of sink
  | 'distant'   // Sink exists but no nearby user input detected
  | 'unknown';  // Could not determine

/**
 * Attack categories based on research sources
 */
export type AttackCategory =
  // Classic injection
  | 'instruction_override'
  | 'role_manipulation'
  | 'boundary_escape'
  | 'data_exfiltration'
  | 'dangerous_commands'
  // Hidden/stealth attacks
  | 'hidden_injection'
  | 'stealth_instruction'
  | 'url_reconstruction'
  // Credential/data theft
  | 'credential_theft'
  | 'credential_exposure'
  // Agent-specific attacks
  | 'cross_agent_escalation' // CAPE
  | 'mcp_attack'
  | 'rag_poisoning'
  | 'persistence'
  | 'goal_hijacking'
  | 'session_smuggling'
  // Code execution
  | 'argument_injection'
  | 'code_injection'
  | 'ssrf'
  // Reconnaissance
  | 'reconnaissance'
  | 'prompt_extraction'
  // Defense evasion
  | 'defense_evasion'
  | 'hierarchy_violation'
  | 'adversarial_suffix'
  // OWASP ASI categories
  | 'ASI01_goal_hijack'
  | 'ASI02_tool_misuse'
  | 'ASI03_privilege_abuse'
  | 'ASI04_supply_chain'
  | 'ASI05_rce'
  | 'ASI06_memory_poisoning'
  | 'ASI07_insecure_comms'
  | 'ASI08_cascading_failures'
  | 'ASI09_trust_exploitation'
  | 'ASI10_rogue_agents'
  // Config issues
  | 'config_vulnerability'
  | 'permission_escalation'
  // Other
  | 'behavior_manipulation'
  | 'platform_specific'
  | 'rendering_exfil'
  | 'path_traversal';

/**
 * Research source identifiers
 */
export type SourceId =
  | 'ai-assistant'
  | 'ACAD-001'
  | 'ACAD-004'
  | 'PII-001'
  | 'PII-002'
  | 'PII-004'
  | 'PIC-001'
  | 'PIC-004'
  | 'PIC-005'
  | 'FND-001'
  | 'THR-002'
  | 'THR-003'
  | 'THR-004'
  | 'THR-005'
  | 'THR-006'
  | 'FRM-002'
  | 'VND-005'
  | 'CMP-002'
  | 'SLOWMIST-MCP'
  | 'custom';

/**
 * Context where the pattern should be matched
 */
export type MatchContext =
  | 'any'
  | 'prompt'
  | 'code'
  | 'config'
  | 'file_path'
  | 'file_write_operation'
  | 'file_create'
  | 'outbound_request'
  | 'email_operation'
  | 'url_parameter'
  | 'generated_code'
  | 'command_template'
  | 'user_input'
  | 'dependency_version';

/**
 * A detection pattern for security scanning
 */
export interface DetectionPattern {
  /** Unique identifier for this pattern */
  name: string;
  /** Regular expression to match */
  pattern: RegExp;
  /** Severity of a match */
  severity: Severity;
  /** Attack category */
  category: AttackCategory;
  /** Research source this pattern came from */
  source: SourceId;
  /** Human-readable description */
  description: string;
  /** Context where this pattern is most relevant */
  context?: MatchContext;
  /** Tags for filtering */
  tags?: string[];
  /** OWASP ASI ID if applicable */
  owaspAsi?: string;
  /** CVE reference if applicable */
  cve?: string;
  /** Example of what this pattern catches */
  example?: string;
  /** Remediation guidance */
  remediation?: string;
}

/**
 * A security finding from pattern matching
 */
export interface Finding {
  /** Pattern that matched */
  pattern: DetectionPattern;
  /** File where finding occurred */
  file: string;
  /** Line number (1-indexed) */
  line: number;
  /** Column number (1-indexed) */
  column: number;
  /** The matched text */
  match: string;
  /** Surrounding context */
  context: string;
  /** Timestamp */
  timestamp: Date;
  /** Auto-classification of why this finding exists */
  classification: FindingClassification;
  /** Original severity before any contextual adjustment */
  originalSeverity: Severity;
  /** Whether severity was downgraded (e.g., test file) */
  severityDowngraded: boolean;
  /** Whether this finding is in a test file */
  isTestFile: boolean;
  /** Taint proximity for dangerous sink patterns */
  taintProximity?: TaintProximity;
  /** Context flow chain (for architectural findings) */
  contextFlowChain?: string[];
}

/**
 * Risk score calculation result
 */
export interface RiskScore {
  /** Total score 0-100 (higher is safer) */
  total: number;
  /** Risk level */
  level: 'critical' | 'high' | 'moderate' | 'low';
  /** Count by severity */
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** OWASP ASI compliance percentage */
  owaspCompliance: number;
}

/**
 * Scan result
 */
export interface ScanResult {
  /** Files scanned */
  filesScanned: number;
  /** Total patterns checked */
  patternsChecked: number;
  /** All findings */
  findings: Finding[];
  /** Risk score */
  riskScore: RiskScore;
  /** Scan duration in ms */
  duration: number;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Pattern category grouping for organization
 */
export interface PatternCategory {
  name: string;
  description: string;
  patterns: DetectionPattern[];
}
