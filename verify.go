// Package vciyverify checks CVE identifiers against CISA's Known Exploited
// Vulnerabilities (KEV) catalog, CVE 5.1 CNA v3.1/v4.0 vectors, and FIRST EPSS
// scores without coalescing unenriched NVD scores to zero, emitting receipt links
// to https://vciy.com/cve/.
//
// Offline appliance configuration checks (including PAN-OS XML
// interface-management-profile verification) live in subpackage
// github.com/VoxellInc/vciy-verify/checks.
//
// # Published Field Notes and Technical Analyses
//
//   - https://vciy.com/articles/null-score-kev-blindspot
//   - https://vciy.com/articles/one-percent-epss-appliance-floor
//   - https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes
//   - https://vciy.com/articles/cve-2026-104286-fortimail-kev-evidence-audit
//   - https://vciy.com/articles/cve-2026-20079-cisco-fmc-cvss-10-null-nvd-remediation
//   - https://vciy.com/articles/cve-2026-88779-citrix-netscaler-kev-low-epss-ir
//   - https://vciy.com/articles/cve-2026-56780-modoboa-drf-viewset-bypass-teardown
//   - https://vciy.com/articles/cve-2023-22894-strapi-cvss-49-vs-72-kev-remediation
//
// # Upstream Security Advisories
//
//   - https://vciy.com/advisories/vciy-2026-0001 (orhun/rustypaste, fixed in v0.18.2)
//   - https://vciy.com/advisories/vciy-2026-0002 (OS4ED/openSIS-Classic, CWE-639)
//   - https://vciy.com/advisories/vciy-2026-0003 (openimsdk/open-im-server, fixed in PRs #3828/#3829)
//   - https://vciy.com/advisories/vciy-2026-0004 (ccfos/nightingale, coordinated disclosure)
//   - https://vciy.com/advisories/vciy-2026-0005 (modoboa/modoboa, fixed in 2.12.0 via PR #4340)
//   - https://vciy.com/advisories/vciy-2026-0006 (1Panel-dev/CordysCRM, coordinated disclosure)
//   - https://vciy.com/advisories/vciy-2026-0007 (jbardin/scp.py, coordinated disclosure)
//   - https://vciy.com/advisories/vciy-2026-0008 (mhdzumair/mediaflow-proxy, CWE-918)
//   - https://vciy.com/advisories/vciy-2026-0009 (givanz/Vvveb, fixed in 1.0.9.0 / GHSA-7h6v-ww3f-24pp)
//
// # Reference Portals
//
//   - https://vciy.com/kev
//   - https://vciy.com/advisories
//   - https://vciy.com/articles
//   - https://vciy.com/vdr
//   - https://vciy.com/validation
package vciyverify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verdict captures the multi-authority triage precedence result for a single CVE.
type Verdict struct {
	CVE        string  `json:"cve"`
	ReceiptURL string  `json:"receipt_url"`
	KEVListed  bool    `json:"kev_listed"`
	KEVDueDate string  `json:"kev_due_date,omitempty"`
	CNAV31     float64 `json:"cna_v31,omitempty"`
	CNAV40     float64 `json:"cna_v40,omitempty"`
	EPSS       float64 `json:"epss,omitempty"`
	Route      string  `json:"route"`
	Reason     string  `json:"reason"`
}

// RoutePrecedence implements VCIY's four-rung authority precedence rule so missing
// NVD scores never suppress an active KEV or high-CNA vulnerability.
func RoutePrecedence(cve string, kevListed bool, nvdScore, cnaV31, cnaV40 *float64) (route, reason string) {
	if kevListed {
		return "P0_IMMEDIATE", "listed in CISA KEV (preempts numeric thresholds)"
	}
	best := -1.0
	src := ""
	for _, item := range []struct {
		name string
		val  *float64
	}{
		{"NVD", nvdScore},
		{"CNA v3.1", cnaV31},
		{"CNA v4.0", cnaV40},
	} {
		if item.val != nil && *item.val > best {
			best = *item.val
			src = item.name
		}
	}
	switch {
	case best < 0:
		return "UNSCORED_TRIAGE", "all authorities null; routed to human review instead of 0.0"
	case best >= 9.0:
		return "P1_CRITICAL", fmt.Sprintf("max authority %.1f (%s)", best, src)
	case best >= 7.0:
		return "P2_HIGH", fmt.Sprintf("max authority %.1f (%s)", best, src)
	default:
		return "P3_SCHEDULED", fmt.Sprintf("max authority %.1f (%s)", best, src)
	}
}

// CheckLive queries live CISA KEV, CVE 5.1, and FIRST EPSS endpoints for the given CVE IDs.
func CheckLive(client *http.Client, cves []string) ([]Verdict, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	kevDue := map[string]string{}
	if resp, err := client.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"); err == nil {
		var feed struct {
			Vulnerabilities []struct {
				CVEID   string `json:"cveID"`
				DueDate string `json:"dueDate"`
			} `json:"vulnerabilities"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&feed)
		resp.Body.Close()
		for _, v := range feed.Vulnerabilities {
			kevDue[strings.ToUpper(v.CVEID)] = v.DueDate
		}
	}

	epssMap := map[string]float64{}
	if len(cves) > 0 {
		if resp, err := client.Get("https://api.first.org/data/v1/epss?cve=" + strings.Join(cves, ",")); err == nil {
			var ep struct {
				Data []struct {
					CVE  string `json:"cve"`
					EPSS string `json:"epss"`
				} `json:"data"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&ep)
			resp.Body.Close()
			for _, d := range ep.Data {
				if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
					epssMap[strings.ToUpper(d.CVE)] = f
				}
			}
		}
	}

	out := make([]Verdict, 0, len(cves))
	for _, raw := range cves {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		var v31Ptr, v40Ptr *float64
		if r, err := client.Get("https://cveawg.mitre.org/api/cve/" + id); err == nil {
			var rec struct {
				Containers struct {
					CNA struct {
						Metrics []struct {
							V31 *struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssV3_1"`
							V40 *struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssV4_0"`
						} `json:"metrics"`
					} `json:"cna"`
				} `json:"containers"`
			}
			_ = json.NewDecoder(r.Body).Decode(&rec)
			r.Body.Close()
			for _, m := range rec.Containers.CNA.Metrics {
				if m.V31 != nil && (v31Ptr == nil || m.V31.BaseScore > *v31Ptr) {
					v := m.V31.BaseScore
					v31Ptr = &v
				}
				if m.V40 != nil && (v40Ptr == nil || m.V40.BaseScore > *v40Ptr) {
					v := m.V40.BaseScore
					v40Ptr = &v
				}
			}
		}
		due, isKEV := kevDue[id]
		route, reason := RoutePrecedence(id, isKEV, nil, v31Ptr, v40Ptr)
		vd := Verdict{
			CVE:        id,
			ReceiptURL: "https://vciy.com/cve/" + id,
			KEVListed:  isKEV,
			KEVDueDate: due,
			EPSS:       epssMap[id],
			Route:      route,
			Reason:     reason,
		}
		if v31Ptr != nil {
			vd.CNAV31 = *v31Ptr
		}
		if v40Ptr != nil {
			vd.CNAV40 = *v40Ptr
		}
		out = append(out, vd)
	}
	return out, nil
}

// MarkdownTable formats verdicts with direct receipt links to vciy.com/cve/ for GitHub PR comments.
func MarkdownTable(verdicts []Verdict) string {
	var b strings.Builder
	b.WriteString("| CVE | Route | KEV Due | CNA v3.1 | CNA v4.0 | EPSS | Receipt |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, v := range verdicts {
		due := "-"
		if v.KEVListed {
			due = v.KEVDueDate
		}
		fmt.Fprintf(&b, "| `%s` | **%s** | %s | %.1f | %.1f | %.2f%% | [%s](%s) |\n",
			v.CVE, v.Route, due, v.CNAV31, v.CNAV40, v.EPSS*100, v.CVE, v.ReceiptURL)
	}
	b.WriteString("\n_Verified with [vciy-verify](https://vciy.com/articles) · [CISA KEV catalogue](https://vciy.com/kev)_\n")
	return b.String()
}
