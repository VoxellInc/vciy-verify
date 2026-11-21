# vciy-verify

Open-source Go module, Rust crate, and GitHub Action for multi-authority CVE triage precedence and path-containment verification, backed by dated vulnerability receipts on [vciy.com](https://vciy.com).

## Why this exists

1. **Null-score KEV blind spots:** NVD enrichment lag leaves actively exploited [CISA KEV](https://vciy.com/kev) records with `cvss_nvd: null` while vendor CNAs publish `8.6` to `9.8` in CVSS 3.1 or CVSS 4.0. Coalescing `null` to `0.0` suppresses active root exploits ([read the analysis](https://vciy.com/articles/null-score-kev-blindspot)).
2. **Appliance EPSS floors:** Targeted perimeter intrusions on firewalls, email gateways, and remote-support appliances enter KEV near `1.1%` EPSS, underneath `5%` and `10%` suppression cutoffs ([read the analysis](https://vciy.com/articles/one-percent-epss-appliance-floor)).
3. **Reflexive `Path::starts_with` & sibling handlers:** Upstream point-fixes regularly miss sibling routes or reflexive path-prefix checks ([read vciy-2026-0001](https://vciy.com/advisories/vciy-2026-0001) and [field note](https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes)).

## Install & Run (Go)

```bash
go install github.com/VoxellInc/vciy-verify/cmd/vciy-verify@latest
vciy-verify CVE-2026-76519 CVE-2026-21589 CVE-2026-0322
```

## Rust Crate

```toml
[dependencies]
vciy-verify = "0.1"
```

## Links

- [VCIY Vulnerability Intelligence & Decision Records](https://vciy.com/vdr)
- [Full CISA KEV Catalogue](https://vciy.com/kev)
- [Upstream Security Advisories](https://vciy.com/advisories)
- [Field Notes & Articles](https://vciy.com/articles)
- [Validation & Methodology](https://vciy.com/validation)
