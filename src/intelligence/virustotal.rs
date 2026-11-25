use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};

use crate::core::analysis::IndicatorKind;

#[derive(Debug, Serialize)]
pub struct Lookup {
    pub source_url: String,
    pub attributes: Option<Attributes>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Attributes {
    pub last_analysis_stats: Option<BTreeMap<String, u32>>,
    pub last_analysis_date: Option<u64>,
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meaningful_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    popular_threat_classification: Option<ThreatClassification>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ThreatClassification {
    suggested_threat_label: Option<String>,
}

#[derive(Deserialize)]
struct Response {
    data: Object,
}

#[derive(Deserialize)]
struct Object {
    id: String,
    attributes: Attributes,
}

fn target(
    indicator: &str,
    kind: IndicatorKind,
) -> Result<(&'static str, &'static str, String), String> {
    let indicator = indicator.trim();
    if IndicatorKind::detect(indicator) != kind {
        return Err("Indicator does not match its detected type.".into());
    }
    match kind {
        IndicatorKind::Ipv4 | IndicatorKind::Ipv6 => {
            Ok(("ip_addresses", "ip-address", indicator.to_ascii_lowercase()))
        }
        IndicatorKind::Domain => Ok((
            "domains",
            "domain",
            indicator.trim_end_matches('.').to_ascii_lowercase(),
        )),
        IndicatorKind::Md5 | IndicatorKind::Sha1 | IndicatorKind::Sha256 => {
            Ok(("files", "file", indicator.to_ascii_lowercase()))
        }
        _ => Err("VirusTotal lookup supports IP addresses, domains, and file hashes.".into()),
    }
}

pub fn lookup(indicator: &str, kind: IndicatorKind) -> Result<Lookup, String> {
    let (endpoint, gui_path, id) = target(indicator, kind)?;
    let key = std::env::var("VIRUSTOTAL_API_KEY").unwrap_or_default();
    let key = key.trim();
    if key.is_empty() {
        return Err("Set VIRUSTOTAL_API_KEY in .env to query VirusTotal.".into());
    }

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .max_redirects(0)
        .https_only(true)
        .build();
    let client = ureq::Agent::new_with_config(config);
    let url = format!("https://www.virustotal.com/api/v3/{endpoint}/{id}");
    let object = match client
        .get(url)
        .header("accept", "application/json")
        .header("x-apikey", key)
        .call()
    {
        Ok(mut response) if response.status().is_success() => {
            let response: Response = response
                .body_mut()
                .read_json()
                .map_err(|_| "Could not read the VirusTotal report.")?;
            Some(response.data)
        }
        Err(ureq::Error::StatusCode(404)) => None,
        Err(ureq::Error::StatusCode(401 | 403)) => {
            return Err("VirusTotal rejected the API key or denied access.".into());
        }
        Err(ureq::Error::StatusCode(429)) => {
            return Err("VirusTotal quota or rate limit exceeded. Try again later.".into());
        }
        Err(ureq::Error::StatusCode(status)) => {
            return Err(format!("VirusTotal returned HTTP {status}."));
        }
        Ok(response) => return Err(format!("VirusTotal returned HTTP {}.", response.status())),
        Err(_) => {
            return Err("Could not reach VirusTotal. Check your network and try again.".into());
        }
    };

    let canonical_id = object
        .as_ref()
        .filter(|object| {
            kind.is_hash() && IndicatorKind::detect(&object.id) == IndicatorKind::Sha256
        })
        .map_or(id.as_str(), |object| object.id.as_str());
    Ok(Lookup {
        source_url: format!("https://www.virustotal.com/gui/{gui_path}/{canonical_id}"),
        attributes: object.map(|object| object.attributes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_supported_indicators_and_normalizes_lookup_ids() {
        use IndicatorKind::*;

        for (input, kind, endpoint, gui_path, id) in [
            ("8.8.8.8", Ipv4, "ip_addresses", "ip-address", "8.8.8.8"),
            (
                "2001:DB8::1",
                Ipv6,
                "ip_addresses",
                "ip-address",
                "2001:db8::1",
            ),
            (" EXAMPLE.COM. ", Domain, "domains", "domain", "example.com"),
            (
                "44D88612FEA8A8F36DE82E1278ABB02F",
                Md5,
                "files",
                "file",
                "44d88612fea8a8f36de82e1278abb02f",
            ),
            (
                "3395856ce81f2b7382dee72602f798b642f14140",
                Sha1,
                "files",
                "file",
                "3395856ce81f2b7382dee72602f798b642f14140",
            ),
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                Sha256,
                "files",
                "file",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ),
        ] {
            assert_eq!(
                target(input, kind).unwrap(),
                (endpoint, gui_path, id.into())
            );
        }
        assert!(target("CVE-2021-44228", Cve).is_err());
        assert!(target("example.com/path", Domain).is_err());
    }
}
