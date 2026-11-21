//! Multi-authority CVE routing precedence and hardened path-containment helpers
//! extracted from [vciy field notes](https://vciy.com/articles) and
//! [vciy upstream advisories](https://vciy.com/advisories).
//!
//! - Null-NVD KEV precedence: <https://vciy.com/articles/null-score-kev-blindspot>
//! - Appliance EPSS floor audit: <https://vciy.com/articles/one-percent-epss-appliance-floor>
//! - Reflexive `Path::starts_with` containment (`vciy-2026-0001`): <https://vciy.com/advisories/vciy-2026-0001>

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
