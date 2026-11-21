//! Multi-authority CVE routing precedence and hardened path-containment helpers
//! extracted from [vciy field notes](https://vciy.com/articles) and
//! [vciy upstream advisories](https://vciy.com/advisories).
//!
//! ## Published Field Notes and Technical Analyses
//!
//! - Null-NVD KEV precedence (`CVE-2026-76519`, `CVE-2026-21589`, `CVE-2026-104935`):
//!   <https://vciy.com/articles/null-score-kev-blindspot>
//! - Appliance EPSS floor audit and PAN-OS isolation (`CVE-2026-0322`, `CVE-2026-102764`, `CVE-2025-61624`):
//!   <https://vciy.com/articles/one-percent-epss-appliance-floor>
//! - Sibling handlers and incomplete upstream CVE fixes (`CVE-2026-90774`, `CVE-2026-91107`, `CVE-2026-69115`):
//!   <https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes>
//! - Fortinet FortiMail KEV forensic audit under null NVD (`CVE-2026-104286`):
//!   <https://vciy.com/articles/cve-2026-104286-fortimail-kev-evidence-audit>
//! - Cisco FMC CVSS 10.0 CNA vs null NVD remediation (`CVE-2026-20079`):
//!   <https://vciy.com/articles/cve-2026-20079-cisco-fmc-cvss-10-null-nvd-remediation>
//! - Citrix NetScaler 0.59% EPSS KEV incident response (`CVE-2026-88779`):
//!   <https://vciy.com/articles/cve-2026-88779-citrix-netscaler-kev-low-epss-ir>
//! - Modoboa DRF ViewSet inheritance bypass teardown (`CVE-2026-56780`, `vciy-2026-0005`):
//!   <https://vciy.com/articles/cve-2026-56780-modoboa-drf-viewset-bypass-teardown>
//! - Strapi KEV remediation when NVD scores 4.9 vs ADP 7.2 (`CVE-2023-22894`):
//!   <https://vciy.com/articles/cve-2023-22894-strapi-cvss-49-vs-72-kev-remediation>
//!
//! ## Upstream Security Advisories
//!
//! - `vciy-2026-0001` (`orhun/rustypaste`, fixed in `v0.18.2`): <https://vciy.com/advisories/vciy-2026-0001>
//! - `vciy-2026-0002` (`OS4ED/openSIS-Classic`, `CWE-639`): <https://vciy.com/advisories/vciy-2026-0002>
//! - `vciy-2026-0003` (`openimsdk/open-im-server`, fixed in PRs #3828/#3829): <https://vciy.com/advisories/vciy-2026-0003>
//! - `vciy-2026-0004` (`ccfos/nightingale`, coordinated disclosure): <https://vciy.com/advisories/vciy-2026-0004>
//! - `vciy-2026-0005` (`modoboa/modoboa`, fixed in `2.12.0` via PR #4340): <https://vciy.com/advisories/vciy-2026-0005>
//! - `vciy-2026-0006` (`1Panel-dev/CordysCRM`, coordinated disclosure): <https://vciy.com/advisories/vciy-2026-0006>
//! - `vciy-2026-0007` (`jbardin/scp.py`, coordinated disclosure): <https://vciy.com/advisories/vciy-2026-0007>
//! - `vciy-2026-0008` (`mhdzumair/mediaflow-proxy`, `CWE-918`): <https://vciy.com/advisories/vciy-2026-0008>
//! - `vciy-2026-0009` (`givanz/Vvveb`, fixed in `1.0.9.0` / `GHSA-7h6v-ww3f-24pp`): <https://vciy.com/advisories/vciy-2026-0009>
//!
//! ## Reference Portals
//!
//! - CISA KEV catalogue with receipts: <https://vciy.com/kev>
//! - Vulnerability Decision Records: <https://vciy.com/vdr>
//! - Validation and methodology: <https://vciy.com/validation>

use std::io::{Error, ErrorKind, Result};
use std::path::{Component, Path, PathBuf};

/// Priority tier returned by [`route_precedence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageRoute {
    P0Immediate,
    P1Critical,
    P2High,
    P3Scheduled,
    UnscoredTriage,
}

/// Evaluates CISA KEV first, then `max(nvd, cna_v31, cna_v40)` without coalescing
/// missing (`None`) NVD scores to `0.0`.
pub fn route_precedence(
    kev_listed: bool,
    nvd: Option<f64>,
    cna_v31: Option<f64>,
    cna_v40: Option<f64>,
) -> TriageRoute {
    if kev_listed {
        return TriageRoute::P0Immediate;
    }
    let best = [nvd, cna_v31, cna_v40]
        .into_iter()
        .flatten()
        .fold(None::<f64>, |acc, x| Some(acc.map_or(x, |a| a.max(x))));
    match best {
        None => TriageRoute::UnscoredTriage,
        Some(s) if s >= 9.0 => TriageRoute::P1Critical,
        Some(s) if s >= 7.0 => TriageRoute::P2High,
        Some(_) => TriageRoute::P3Scheduled,
    }
}

/// Canonical VCIY receipt URL for a CVE identifier (`https://vciy.com/cve/<CVE>`).
pub fn receipt_url(cve_id: &str) -> String {
    format!("https://vciy.com/cve/{}", cve_id.trim().to_ascii_uppercase())
}

/// Lexically joins `part` onto `base`, rejecting both parent traversal and
/// reflexive equality (`joined == cleaned_base`), closing the `vciy-2026-0001` class.
pub fn safe_contained_join<P1: AsRef<Path>, P2: AsRef<Path>>(base: P1, part: P2) -> Result<PathBuf> {
    let normalize = |p: &Path| -> PathBuf {
        let mut out = PathBuf::new();
        for c in p.components() {
            match c {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        out
    };
    let cleaned_base = normalize(base.as_ref());
    let joined = normalize(&base.as_ref().join(part));
    if joined == cleaned_base || !joined.starts_with(&cleaned_base) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "reflexive base match or directory traversal rejected",
        ));
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_nvd_never_coalesces_to_zero() {
        assert_eq!(route_precedence(true, None, None, None), TriageRoute::P0Immediate);
        assert_eq!(route_precedence(false, None, None, Some(9.3)), TriageRoute::P1Critical);
        assert_eq!(route_precedence(false, None, None, None), TriageRoute::UnscoredTriage);
    }

    #[test]
    fn safe_join_rejects_reflexive_and_traversal() {
        let base = Path::new("/srv/uploads/url");
        assert!(safe_contained_join(base, ".").is_err());
        assert!(safe_contained_join(base, "nested/..").is_err());
        assert!(safe_contained_join(base, "../etc/passwd").is_err());
        assert_eq!(
            safe_contained_join(base, "item.txt").unwrap(),
            PathBuf::from("/srv/uploads/url/item.txt")
        );
    }
}
