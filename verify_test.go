package vciyverify

import (
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
