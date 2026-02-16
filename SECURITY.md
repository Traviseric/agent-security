# Security Policy

## Reporting a Vulnerability

We take security issues seriously. If you discover a security vulnerability in agent-security, please report it privately.

### Where to Report

**Email**: security@empoweredhumanity.ai

**Include in your report**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Critical issues within 30 days, others within 90 days

### Disclosure Policy

- Please allow us reasonable time to fix the issue before public disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will notify you when the fix is released

### Security Advisory Process

1. We validate the report
2. We develop and test a fix
3. We release a patched version
4. We publish a security advisory (GitHub Security Advisories)
5. We credit the reporter (if desired)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Security Best Practices

When using agent-security in your projects:

1. **Keep Updated**: Use the latest version to get security fixes
2. **Dependency Scanning**: Regularly update dependencies
3. **Secure Configuration**: Follow the security guidelines in the documentation
4. **False Positives**: Report pattern false positives to help improve detection
5. **Defense in Depth**: Use this scanner as part of a multi-layer security strategy

## Known Limitations

- This scanner detects patterns, not intent. Manual review is required for final security assessment.
- Some attack vectors may not be detected if they use novel techniques not in the pattern library.
- The scanner does not analyze runtime behavior, only static code and content.

## Security Features

- **Pattern-based detection**: 190 security patterns with 4 intelligence layers
- **OWASP ASI coverage**: All 10 OWASP Agentic Security Issues
- **No network calls**: All scanning happens locally
- **No data collection**: Your code never leaves your machine
- **Open source**: All patterns are transparent and auditable

## Responsible Disclosure Examples

Examples of what we consider reportable:
- Pattern bypasses that allow known attacks to evade detection
- False negatives on critical security patterns
- Code execution vulnerabilities in the scanner itself
- Dependency vulnerabilities with active exploits

Examples of what we do NOT consider reportable:
- Feature requests for new patterns (submit as GitHub issues)
- False positives (submit as GitHub issues)
- Missing detection for novel, unpublished attack vectors (submit pattern suggestions)
- Performance issues (submit as GitHub issues)

## Security Update Notifications

Subscribe to security updates:
- **GitHub**: Watch this repository for security advisories
- **npm**: `npm audit` will show vulnerabilities
- **Email**: security@empoweredhumanity.ai (for critical advisories)

## Bug Bounty

We currently do not offer a bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will publicly acknowledge your contribution.

## Questions?

For non-security questions, please use GitHub Issues.
For security concerns, email security@empoweredhumanity.ai.
