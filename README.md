# Building an AI Threat Intelligence Analyst

## Project Overview

The goal of this project is to develop an AI-powered tool that assists cybersecurity analysts in investigating potential threats and known software vulnerabilities.

The system will accept various inputs, including IP addresses, domains, file hashes, CVE identifiers, and software packages with specific versions. It will automatically gather relevant information from public threat intelligence sources, vulnerability databases, and security reports.

Based on the collected data, an AI model will generate a structured, easy-to-understand report containing identified threats or vulnerabilities, supporting evidence, source references, risk assessments, and recommended actions.

The system will distinguish verified information from potential hypotheses, highlight uncertainties, and support human decision-making rather than performing autonomous security actions.

## Proposed Solution

The proposed solution is an AI-assisted system that automates the process of collecting, analyzing, and summarizing cybersecurity threat intelligence.

Users will be able to submit a suspicious indicator or a potentially vulnerable software component. Based on the input type, the system will search relevant public sources, collect available information, and use AI to analyze the findings.

The results will be presented in a clear, structured report, helping analysts quickly understand potential threats, assess their severity, and identify possible next steps.

## Run VirusTotal analysis

1. Copy `.env.example` to `.env` and set `VIRUSTOTAL_API_KEY`.
2. Start Ollama locally on port `11434` and run `ollama pull qwen3.5:9b`. Set `OLLAMA_MODEL` in `.env` to use another installed model.
3. Run `cargo run` and analyze an IP address, domain, or MD5, SHA-1, or SHA-256 file hash.

The app retrieves existing VirusTotal reports and sends selected fields to Ollama. The report includes VirusTotal scan counts and a link to the source. Indicators without usable scanner evidence receive an unknown risk rating. CVE and package analysis are planned.

## Key Features

- **Multiple Input Types** - Support for IP addresses, domains, file hashes, CVE identifiers, and software packages with specific versions.
- **Automated Data Collection** - Retrieval of relevant information from public threat intelligence sources, vulnerability databases, and security reports.
- **AI-Powered Analysis** - Interpretation and summarization of collected data to identify potential threats, vulnerabilities, and relevant security context.
- **Risk Assessment** - Evaluation of potential security risks based on available evidence, including severity and uncertainty.
- **Structured Reports** - Generation of clear, readable reports containing findings, technical details, and recommended actions.
- **Source References** - Links to original sources supporting the reported findings.
- **Evidence and Hypothesis Separation** - Clear distinction between verified information, possible interpretations, and missing evidence.
- **Human Oversight** - The system provides recommendations but leaves security decisions and actions to the user.

## Limitations & Security

The system will rely on publicly available information, which may be incomplete, outdated, or inconsistent across different sources.

AI-generated analysis may contain inaccuracies or incorrect interpretations. Therefore, the system will provide source references, highlight uncertainties, and distinguish verified evidence from hypotheses.

The tool is intended to support cybersecurity analysts rather than replace them. All security-related decisions will remain under human control, and autonomous actions affecting external systems will be disabled by default.

## Expected Deliverables

- **Working Prototype** - A functional application capable of analyzing supported threat indicators and software vulnerabilities.
- **Architecture Documentation** - An overview of the system's components, data sources, and analysis workflow.
- **Test Suite** - A collection of representative test cases, including ambiguous and conflicting scenarios.
- **Evaluation Results** - A summary of the system's performance based on the defined evaluation criteria.
- **Limitations Report** - Documentation of known limitations, potential risks, and areas for future improvement.
