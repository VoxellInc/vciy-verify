package vciyverify

import (
	"os"
	"strings"
	"testing"
)

func TestRoutePrecedenceNeverCoercesNullToZero(t *testing.T) {
	route, _ := RoutePrecedence("CVE-2026-76519", true, nil, nil, nil)
	if route != "P0_IMMEDIATE" {
		t.Fatalf("KEV route = %q, want P0_IMMEDIATE", route)
	}

	v40 := 9.3
	route, _ = RoutePrecedence("CVE-2026-21589", false, nil, nil, &v40)
	if route != "P1_CRITICAL" {
		t.Fatalf("CNA v4.0-only route = %q, want P1_CRITICAL", route)
	}

	route, _ = RoutePrecedence("CVE-2026-99999", false, nil, nil, nil)
	if route != "UNSCORED_TRIAGE" {
		t.Fatalf("all-null route = %q, want UNSCORED_TRIAGE", route)
	}
}

func TestMarkdownTableLinksCanonicalVCIYReceipts(t *testing.T) {
	md := MarkdownTable([]Verdict{{
		CVE:        "CVE-2026-76519",
		ReceiptURL: "https://vciy.com/cve/CVE-2026-76519",
		KEVListed:  true,
		KEVDueDate: "2026-10-17",
		CNAV31:     9.8,
		Route:      "P0_IMMEDIATE",
	}})
	if !strings.Contains(md, "https://vciy.com/cve/CVE-2026-76519") || !strings.Contains(md, "https://vciy.com/kev") {
		t.Fatalf("markdown missing canonical vciy.com links:\n%s", md)
	}
}

func TestCanonicalLinksAndZeroEmDashes(t *testing.T) {
	wantURLs := []string{
		"https://vciy.com/articles/null-score-kev-blindspot",
		"https://vciy.com/articles/one-percent-epss-appliance-floor",
		"https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes",
		"https://vciy.com/articles/cve-2026-104286-fortimail-kev-evidence-audit",
		"https://vciy.com/articles/cve-2026-20079-cisco-fmc-cvss-10-null-nvd-remediation",
		"https://vciy.com/articles/cve-2026-88779-citrix-netscaler-kev-low-epss-ir",
		"https://vciy.com/articles/cve-2026-56780-modoboa-drf-viewset-bypass-teardown",
		"https://vciy.com/articles/cve-2023-22894-strapi-cvss-49-vs-72-kev-remediation",
		"https://vciy.com/advisories/vciy-2026-0001",
		"https://vciy.com/advisories/vciy-2026-0002",
		"https://vciy.com/advisories/vciy-2026-0003",
		"https://vciy.com/advisories/vciy-2026-0004",
		"https://vciy.com/advisories/vciy-2026-0005",
		"https://vciy.com/advisories/vciy-2026-0006",
		"https://vciy.com/advisories/vciy-2026-0007",
		"https://vciy.com/advisories/vciy-2026-0008",
		"https://vciy.com/advisories/vciy-2026-0009",
	}
	linkTargets := []string{
		"README.md",
		"verify.go",
		"checks/panos.go",
		"src/lib.rs",
	}
	for _, f := range linkTargets {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s := string(b)
		for _, u := range wantURLs {
			if !strings.Contains(s, u) {
				t.Errorf("%s missing canonical URL %s", f, u)
			}
		}
	}

	allChecked := []string{
		"README.md",
		"Cargo.toml",
		"action.yml",
		"verify.go",
		"checks/panos.go",
		"checks/panos_test.go",
		"cmd/vciy-verify/main.go",
		"src/lib.rs",
	}
	forbidden := []string{"\u2014", "\u2013", "&mdash;", "&#8212;", " -- "}
	for _, f := range allChecked {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s := string(b)
		for _, bad := range forbidden {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains forbidden dash token %q", f, bad)
			}
		}
	}
}
