# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains GitHub Security Advisory (GHSA) JSON files for npm packages, focused on Software Composition Analysis (SCA). The collection includes vulnerability data for various npm packages including security details, CVE numbers, affected versions, and remediation information.

## Repository Structure

- **Root directory**: Contains GHSA JSON files following the naming pattern `npm-GHSA-{identifier}.json`
- **File format**: Each file contains structured vulnerability data including:
  - Vulnerability summary and detailed description
  - CVE aliases and severity scores (CVSS)
  - Affected package versions and version ranges
  - References to security advisories and patches
  - Database-specific metadata

## Security Advisory Data Format

Each JSON file follows the GitHub Advisory Database schema (version 1.7.3) and includes:

- `id`: GHSA identifier
- `summary`: Brief vulnerability description
- `details`: Comprehensive vulnerability analysis
- `affected`: Array of affected packages with version ranges
- `references`: Links to advisories, patches, and related resources
- `severity`: CVSS scoring information
- `database_specific`: GitHub-specific metadata including CWE classifications

## Common Workflows

### Analyzing Security Data
- Use JSON parsing tools to extract specific vulnerability information
- Filter by severity levels, CWE types, or affected packages
- Cross-reference CVE numbers with external databases

### Working with Advisory Files
- Files are read-only security data - avoid modifications
- Use standard JSON tools for analysis and reporting
- Maintain file naming convention when adding new advisories

## Data Sources

The advisory files are sourced from the GitHub Advisory Database and contain information about:
- Cross-site scripting (XSS) vulnerabilities
- Path traversal and file upload issues  
- Open redirect vulnerabilities
- Input sanitization problems

## Security Considerations

- These files contain vulnerability descriptions for educational/defensive purposes
- Do not use vulnerability details for malicious purposes
- Focus on understanding defensive security measures and proper remediation