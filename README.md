# vciy-verify

Open-source Go module, Rust crate, and GitHub Action for multi-authority CVE triage precedence, path-containment verification, and offline appliance configuration checks, backed by dated vulnerability receipts on [vciy.com](https://vciy.com).

## Why this exists

1. **Null-score KEV blind spots:** NVD enrichment lag leaves actively exploited [CISA KEV](https://vciy.com/kev) records with `cvss_nvd: null` while vendor CNAs publish `8.6` to `10.0` in CVSS 3.1 or CVSS 4.0. Coalescing `null` to `0.0` suppresses active root exploits ([read the analysis](https://vciy.com/articles/null-score-kev-blindspot)).
2. **Appliance EPSS floors:** Targeted perimeter intrusions on firewalls, email gateways, ADCs, and remote-support appliances enter KEV near `0.59%` to `1.22%` EPSS, underneath `5%` and `10%` suppression cutoffs ([read the analysis](https://vciy.com/articles/one-percent-epss-appliance-floor)).
3. **Reflexive `Path::starts_with` & sibling handlers:** Upstream point-fixes regularly miss sibling routes, ViewSet actions, or reflexive path-prefix checks ([read vciy-2026-0001](https://vciy.com/advisories/vciy-2026-0001), [vciy-2026-0005](https://vciy.com/advisories/vciy-2026-0005), and [field note](https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes)).

## Install & Run (Go)

```bash
go install github.com/VoxellInc/vciy-verify/cmd/vciy-verify@v0.2.0
vciy-verify CVE-2026-76519 CVE-2026-20079 CVE-2026-0322
vciy-verify -panos-xml running-config.xml
```

### Offline PAN-OS `interface-management-profile` Check (`checks` subpackage)

```go
package main

import (
	"fmt"

	"github.com/VoxellInc/vciy-verify/checks"
)

func main() {
	findings, err := checks.AuditPANOSConfigFile("running-config.xml")
	if err != nil {
		panic(err)
	}
	for _, f := range findings {
		fmt.Println(f.Status, f.ProfileName, f.Services, f.ReceiptURL)
	}
}
```

## Rust Crate

```toml
[dependencies]
vciy-verify = "0.2"
```

## Published Field Notes & Technical Analyses

- [The Null-Score Trap: Why NVD-Gated Scanners Miss Three Active KEV Exploits](https://vciy.com/articles/null-score-kev-blindspot) (`CVE-2026-76519`, `CVE-2026-21589`, `CVE-2026-104935`)
- [The One-Percent Floor: When EPSS Cutoffs Silence Active Appliance Exploits](https://vciy.com/articles/one-percent-epss-appliance-floor) (`CVE-2026-0322`, `CVE-2026-102764`, `CVE-2025-61624`)
- [One Handler Down, Two Siblings Open: Auditing Upstream Security Patches Before Closing the Ticket](https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes) (`CVE-2026-90774`, `CVE-2026-91107`, `CVE-2026-69115`)
- [CVE-2026-104286 Fortinet FortiMail: Defending Your Audit Call When KEV Demands Forensics and NVD Shows Null](https://vciy.com/articles/cve-2026-104286-fortimail-kev-evidence-audit)
- [CVE-2026-20079 Cisco FMC: Patch Precedence When a CVSS 10.0 Root Auth Bypass Sits at Null in NVD for Six Months](https://vciy.com/articles/cve-2026-20079-cisco-fmc-cvss-10-null-nvd-remediation)
- [CVE-2026-88779 Citrix NetScaler: Incident Response When a 0.59% EPSS Bug Hits KEV Seven Days After Your Last Patch](https://vciy.com/articles/cve-2026-88779-citrix-netscaler-kev-low-epss-ir)
- [CVE-2026-56780 Modoboa: Why 2.9.0 Closed One Endpoint While ViewSet Inheritance Left Tenant Auth Open Until 2.12.0](https://vciy.com/articles/cve-2026-56780-modoboa-drf-viewset-bypass-teardown)
- [CVE-2023-22894 Strapi: Running a 72-Hour KEV Clock When NVD Scores 4.9 Medium and ADP Scores 7.2 High](https://vciy.com/articles/cve-2023-22894-strapi-cvss-49-vs-72-kev-remediation)

## Upstream Security Advisories

- [vciy-2026-0001](https://vciy.com/advisories/vciy-2026-0001): `orhun/rustypaste` incomplete `CVE-2026-90774` fix and sibling path traversal (`CWE-22`, fixed in `v0.18.2`)
- [vciy-2026-0002](https://vciy.com/advisories/vciy-2026-0002): `OS4ED/openSIS-Classic` residual authorization logic defects for `CVE-2026-91107` (`CWE-639`)
- [vciy-2026-0003](https://vciy.com/advisories/vciy-2026-0003): `openimsdk/open-im-server` missing `authverify` checks in sibling RPC handlers for `CVE-2026-69115` (`CWE-862`, fixed in PRs #3828 and #3829)
- [vciy-2026-0004](https://vciy.com/advisories/vciy-2026-0004): `ccfos/nightingale` datasource proxy authentication boundary (`CWE-306`, coordinated disclosure)
- [vciy-2026-0005](https://vciy.com/advisories/vciy-2026-0005): `modoboa/modoboa` incomplete fixes for `CVE-2026-56780` and `CVE-2026-90910` in REST API viewsets (`CWE-639`, fixed in `2.12.0` via PR #4340)
- [vciy-2026-0006](https://vciy.com/advisories/vciy-2026-0006): `1Panel-dev/CordysCRM` sibling field resolution permission checks (`CWE-862`, coordinated disclosure)
- [vciy-2026-0007](https://vciy.com/advisories/vciy-2026-0007): `jbardin/scp.py` directory push path containment (`CWE-22`, coordinated disclosure)
- [vciy-2026-0008](https://vciy.com/advisories/vciy-2026-0008): `mhdzumair/mediaflow-proxy` missing internal-address validation in HLS, DASH, and transcode routes (`CWE-918`)
- [vciy-2026-0009](https://vciy.com/advisories/vciy-2026-0009): `givanz/Vvveb` incomplete `CVE-2026-41934` template upload restriction in `MediaTrait` (`CWE-434`, fixed in `1.0.9.0` / `GHSA-7h6v-ww3f-24pp`)

## Links

- [VCIY Vulnerability Intelligence & Decision Records](https://vciy.com/vdr)
- [Full CISA KEV Catalogue](https://vciy.com/kev)
- [Upstream Security Advisories](https://vciy.com/advisories)
- [Field Notes & Articles](https://vciy.com/articles)
- [Validation & Methodology](https://vciy.com/validation)
