# Vulnerability Classification System - Detailed Guide

This document provides detailed explanations for each dimension of our 6-dimensional vulnerability classification system.

## Temporal Classification Dimensions

### 1. **Zero-day**
- **Definition**: Recently disclosed vulnerabilities where patches may not be widely available yet
- **Characteristics**:
  - Disclosed within the last 0-30 days
  - Patches may exist but haven't been widely tested or adopted
  - Limited public documentation or analysis
  - High uncertainty about real-world impact
- **Example**: A new XSS vulnerability in React disclosed yesterday with a patch released but not yet in stable releases

### 2. **Active-exploitation**
- **Definition**: Vulnerabilities known to be actively exploited in the wild
- **Characteristics**:
  - Evidence of exploitation in production environments
  - May have public exploit code available
  - Often referenced in threat intelligence reports
  - Could be recent or older vulnerabilities that gained exploitation activity
- **Example**: Log4j vulnerability (CVE-2021-44228) which had widespread active exploitation

### 3. **Stable-mature**
- **Definition**: Well-documented vulnerabilities with established remediation practices
- **Characteristics**:
  - Disclosed 30+ days ago with stable patches available
  - Comprehensive documentation and analysis available
  - Clear remediation paths established
  - No current evidence of active exploitation
  - Community consensus on impact and fixes
- **Example**: Most CVEs that have been patched and documented for several months

### 4. **Legacy**
- **Definition**: Old vulnerabilities in deprecated or end-of-life components
- **Characteristics**:
  - Affects software versions that are no longer supported
  - May not have patches available due to end-of-life status
  - Often requires architectural changes rather than simple updates
  - Lower priority due to reduced usage of affected versions
- **Example**: Vulnerabilities in Internet Explorer 6 or PHP 5.x versions

## Classification Logic for Temporal Dimension

When classifying temporally, consider:

1. **Disclosure date** - How recently was this vulnerability made public?
2. **Patch availability** - Are stable, tested patches widely available?
3. **Exploitation status** - Is there evidence of active exploitation?
4. **Component lifecycle** - Is the affected software still actively maintained?
5. **Documentation maturity** - How well understood is the vulnerability?

## Overlap Scenarios

Some vulnerabilities might seem to fit multiple categories:

- **Zero-day + Active-exploitation**: A recently disclosed vulnerability that's immediately being exploited
- **Stable-mature + Active-exploitation**: An older, well-documented vulnerability that suddenly sees new exploitation activity
- **Legacy + Active-exploitation**: Old vulnerabilities in deprecated systems that are targeted because they're unpatched

In these cases, prioritize based on **current risk level**:
- Active exploitation takes precedence over age
- Zero-day takes precedence if exploitation evidence is limited
- Legacy is used when the component itself is end-of-life regardless of exploitation

## Complete Classification Framework

### 1. Verifiability
- **verifiable**: Objective code/config patterns can confirm presence (e.g., specific function names, configuration settings)
- **non-verifiable**: Requires behavioral analysis or complex logic inspection
- **partially-verifiable**: Some indicators present but incomplete confirmation possible

### 2. Exploitability Context
- **direct-dependency**: Vulnerability in directly imported package
- **transitive-dependency**: Vulnerability in sub-dependency
- **development-only**: Only affects dev/test environments
- **runtime-critical**: Affects production execution paths

### 3. Attack Vector Accessibility
- **user-input-required**: Needs malicious user input to trigger
- **network-accessible**: Exploitable via network requests
- **local-only**: Requires local file system access
- **configuration-dependent**: Only exploitable with specific configs

### 4. Impact Scope
- **data-confidentiality**: Information disclosure/leakage
- **data-integrity**: Data modification/corruption
- **system-availability**: DoS/service disruption
- **code-execution**: RCE/arbitrary code execution
- **privilege-escalation**: Authentication/authorization bypass

### 5. Remediation Complexity
- **simple-update**: Direct version bump fixes issue
- **breaking-change**: Update requires code modifications
- **no-fix-available**: Vulnerability unpatched
- **workaround-available**: Mitigation possible without update
- **architecture-change**: Requires significant refactoring

### 6. Temporal Classification
- **zero-day**: Recently disclosed, patches may not be widely available
- **active-exploitation**: Known to be exploited in the wild
- **stable-mature**: Well-documented with established remediation
- **legacy**: Old vulnerability in deprecated component

## Usage Guidelines

This temporal dimension helps prioritize remediation efforts by understanding the vulnerability's maturity and current threat landscape position. Use this framework to:

1. **Prioritize security responses** based on exploitation status and patch availability
2. **Plan remediation efforts** considering the maturity of available fixes
3. **Assess risk levels** by understanding the vulnerability's position in its lifecycle
4. **Make informed decisions** about resource allocation for vulnerability management