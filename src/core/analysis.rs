use std::fmt::Write as _;
use std::net::IpAddr;

use super::risk::{Confidence, RiskLevel};

/// The kind of indicator the user submitted, detected from its format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndicatorKind {
    Ipv4,
    Ipv6,
    Domain,
    Md5,
    Sha1,
    Sha256,
    Cve,
    Package,
    Unknown,
}

impl IndicatorKind {
    /// Detects the indicator kind from raw user input.
    pub fn detect(input: &str) -> Self {
        let s = input.trim();
        if s.is_empty() {
            return Self::Unknown;
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return if ip.is_ipv4() { Self::Ipv4 } else { Self::Ipv6 };
        }
        if is_cve(s) {
            return Self::Cve;
        }
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            return match s.len() {
                32 => Self::Md5,
                40 => Self::Sha1,
                64 => Self::Sha256,
                _ => Self::Unknown,
            };
        }
        if parse_package(s).is_some() {
            return Self::Package;
        }
        if is_domain(s) {
            return Self::Domain;
        }
        Self::Unknown
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Domain => "Domain",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Cve => "CVE",
            Self::Package => "Package",
            Self::Unknown => "Unknown",
        }
    }

    #[allow(dead_code)]
    pub fn is_ip(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }

    #[allow(dead_code)]
    pub fn is_hash(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1 | Self::Sha256)
    }
}

fn is_cve(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, id)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && id.len() >= 4
        && id.chars().all(|c| c.is_ascii_digit())
}

/// A software package reference such as `lodash@4.17.20` or `requests==2.19.0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRef {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

pub fn parse_package(s: &str) -> Option<PackageRef> {
    let (name, version, ecosystem) = if let Some((name, version)) = s.split_once("==") {
        (name, version, "PyPI")
    } else {
        let (name, version) = s.rsplit_once('@')?;
        (name, version, "npm")
    };
    let name_ok = !name.is_empty()
        && name != "@"
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./@".contains(c));
    let version_ok = version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c));
    (name_ok && version_ok).then(|| PackageRef {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
    })
}

fn is_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let labels_ok = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    let tld = labels.last().copied().unwrap_or_default();
    labels_ok && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

/// One step of the analysis pipeline.
#[derive(Clone, Copy, Debug)]
pub struct PipelineStep {
    pub label: &'static str,
    pub source: &'static str,
}

const fn step(label: &'static str, source: &'static str) -> PipelineStep {
    PipelineStep { label, source }
}

/// Returns the ordered analysis steps for the given indicator kind.
pub fn pipeline(kind: IndicatorKind) -> Vec<PipelineStep> {
    let mut steps = vec![step("Detecting indicator type", "Local parser")];
    match kind {
        IndicatorKind::Cve => steps.extend([
            step("Querying vulnerability database", "NVD"),
            step("Checking known exploited vulnerabilities", "CISA KEV"),
        ]),
        IndicatorKind::Package => steps.extend([
            step("Querying open-source advisories", "OSV.dev"),
            step("Querying vulnerability database", "NVD"),
            step("Checking known exploited vulnerabilities", "CISA KEV"),
        ]),
        _ => steps.extend([
            step("Querying threat intelligence", "VirusTotal"),
            step("Checking local history", "SQLite cache"),
        ]),
    }
    steps.push(step("Generating AI report", "AI analyst"));
    steps
}

/// Runs the analysis backend for an indicator.
///
/// Replace this stub once the `intelligence`, `storage`, and `ai` modules are wired up.
pub async fn run(_indicator: String, _kind: IndicatorKind) -> Result<Report, String> {
    Err("Backend intelligence sources and AI provider are not connected yet.".to_string())
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub title: String,
    pub detail: String,
    pub severity: RiskLevel,
}

/// A statement backed by a concrete source.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub statement: String,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct SourceRef {
    pub name: String,
    pub url: String,
}

/// The final report presented to the analyst.
#[derive(Clone, Debug)]
pub struct Report {
    pub indicator: String,
    pub kind: IndicatorKind,
    pub risk: RiskLevel,
    pub score: u8,
    pub confidence: Confidence,
    pub verdict: String,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub hypotheses: Vec<String>,
    pub gaps: Vec<String>,
    pub recommendations: Vec<String>,
    pub sources: Vec<SourceRef>,
    pub elapsed_ms: u64,
}

impl Report {
    /// Plain markdown version of the report, used by "Copy report".
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        let _ = writeln!(md, "# Threat report: `{}` ({})\n", self.indicator, self.kind.label());
        let _ = writeln!(
            md,
            "**Risk:** {} ({}/100) · **Confidence:** {}\n",
            self.risk.label(),
            self.score,
            self.confidence.label()
        );
        let _ = writeln!(md, "**Verdict:** {}\n", self.verdict);
        let _ = writeln!(md, "## Summary\n{}\n", self.summary);
        let _ = writeln!(md, "## Findings");
        for f in &self.findings {
            let _ = writeln!(md, "- **[{}] {}**: {}", f.severity.label(), f.title, f.detail);
        }
        let _ = writeln!(md, "\n## Verified evidence");
        for e in &self.evidence {
            let _ = writeln!(md, "- {} _(source: {})_", e.statement, e.source);
        }
        let _ = writeln!(md, "\n## Hypotheses (unverified)");
        for h in &self.hypotheses {
            let _ = writeln!(md, "- {h}");
        }
        let _ = writeln!(md, "\n## Gaps & uncertainties");
        for g in &self.gaps {
            let _ = writeln!(md, "- {g}");
        }
        let _ = writeln!(md, "\n## Recommended actions");
        for (i, r) in self.recommendations.iter().enumerate() {
            let _ = writeln!(md, "{}. {r}", i + 1);
        }
        let _ = writeln!(md, "\n## Sources");
        for s in &self.sources {
            let _ = writeln!(md, "- [{}]({})", s.name, s.url);
        }
        md
    }
}

#[cfg(test)]
mod tests {
    use super::IndicatorKind::*;
    use super::*;

    #[test]
    fn detects_indicator_kinds() {
        let cases = [
            ("185.220.101.4", Ipv4),
            ("  8.8.8.8 ", Ipv4),
            ("2001:4860:4860::8888", Ipv6),
            ("login-paypa1.com", Domain),
            ("sub.example.co.uk", Domain),
            ("44d88612fea8a8f36de82e1278abb02f", Md5),
            ("3395856ce81f2b7382dee72602f798b642f14140", Sha1),
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                Sha256,
            ),
            ("CVE-2021-44228", Cve),
            ("cve-2024-3094", Cve),
            ("lodash@4.17.20", Package),
            ("@angular/core@17.0.1", Package),
            ("requests==2.19.0", Package),
            ("", Unknown),
            ("hello world", Unknown),
            ("abc123", Unknown),
            ("999.1.1.1", Unknown),
            ("lodash@latest", Unknown),
        ];
        for (input, expected) in cases {
            assert_eq!(IndicatorKind::detect(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn parses_packages() {
        let p = parse_package("@angular/core@17.0.1").unwrap();
        assert_eq!(p.name, "@angular/core");
        assert_eq!(p.version, "17.0.1");
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(parse_package("requests==2.19.0").unwrap().ecosystem, "PyPI");
    }
}
