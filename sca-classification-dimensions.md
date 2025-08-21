# SCA Vulnerability Classification Dimensions

This document defines the 6 primary dimensions for classifying Software Composition Analysis (SCA) vulnerabilities in an automated triage system.

## 1. Verifiability
- **Verifiable**: Objective code/config patterns can confirm presence
- **Non-verifiable**: Requires behavioral analysis or complex logic inspection
- **Partially verifiable**: Some indicators present but incomplete confirmation possible

## 2. Exploitability Context
- **Direct dependency**: Vulnerability in directly imported package
- **Transitive dependency**: Vulnerability in sub-dependency
- **Development-only**: Only affects dev/test environments
- **Runtime-critical**: Affects production execution paths

## 3. Attack Vector Accessibility
- **User input required**: Needs malicious user input to trigger
- **Network accessible**: Exploitable via network requests
- **Local only**: Requires local file system access
- **Configuration dependent**: Only exploitable with specific configs

## 4. Impact Scope
- **Data confidentiality**: Information disclosure/leakage
- **Data integrity**: Data modification/corruption
- **System availability**: DoS/service disruption
- **Code execution**: RCE/arbitrary code execution
- **Privilege escalation**: Authentication/authorization bypass

## 5. Remediation Complexity
- **Simple update**: Direct version bump fixes issue
- **Breaking change**: Update requires code modifications
- **No fix available**: Vulnerability unpatched
- **Workaround available**: Mitigation possible without update
- **Architecture change**: Requires significant refactoring

## 6. Temporal Classification
- **Zero-day**: Recently disclosed, patches may not be widely available
- **Active exploitation**: Known to be exploited in the wild
- **Stable/mature**: Well-documented with established remediation
- **Legacy**: Old vulnerability in deprecated component

## Usage Notes

These dimensions are designed for objective, automated classification without requiring:
- Business context knowledge
- Manual vulnerability assessment
- Application-specific risk analysis

Each dimension provides actionable information for vulnerability triage prioritization and remediation planning.