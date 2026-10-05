package zone

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParsePatchAndApplyAAndTXT(t *testing.T) {
	base, _ := NewSnapshot("lab.test.", 11, mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400}))
	text := `; small record patch against serial 11
DEL www.lab.test. 3600 IN A 127.0.0.21 ; remove secondary address
ADD www.lab.test. 600 IN TXT "patched label"
ADD host3.lab.test. 600 IN A 127.0.0.33
`
	ops, err := ParsePatch(strings.NewReader(text), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 3 || ops[0].Line != 2 || ops[0].Action != "DEL" {
		t.Fatalf("parsed ops = %#v", ops)
	}
	if got := ops[2].RR.Header().Ttl; got != 600 {
		t.Fatalf("explicit TTL = %d, want 600", got)
	}

	candidate, err := ApplyPatch(base, ops, Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Serial != 11 {
		t.Fatalf("candidate must retain base serial until publish, got %d", candidate.Serial)
	}
	as, found := candidate.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 1 || as[0].(*dns.A).A.String() != "127.0.0.20" {
		t.Fatalf("candidate www A = %v found=%v", as, found)
	}
	txts, found := candidate.Lookup("www.lab.test.", dns.TypeTXT)
	if !found || len(txts) != 2 {
		t.Fatalf("candidate www TXT count = %d found=%v", len(txts), found)
	}
	host3, found := candidate.Lookup("host3.lab.test.", dns.TypeA)
	if !found || host3[0].Header().Ttl != 600 {
		t.Fatalf("host3 = %v found=%v", host3, found)
	}

	changes := Diff(base, candidate)
	var adds, dels []Change
	for _, c := range changes {
		if c.Action == "ADD" {
			adds = append(adds, c)
		} else {
			dels = append(dels, c)
		}
	}
	if len(dels) != 1 || CanonicalText(dels[0].RR) != "www.lab.test. 3600 IN A 127.0.0.21" {
		t.Fatalf("deletions = %#v", dels)
	}
	if len(adds) != 2 {
		t.Fatalf("additions = %#v", adds)
	}
}

func TestParsePatchRequiresCompleteExplicitRecord(t *testing.T) {
	cases := map[string]string{
		"unknown action": "CHANGE host.lab.test. 3600 IN A 1.2.3.4\n",
		"missing TTL":    "ADD host.lab.test. IN A 1.2.3.4\n",
		"directive":      "$TTL 3600\nADD host.lab.test. IN A 1.2.3.4\n",
		"truncated RR":   "ADD host.lab.test. 3600 IN\n",
		"empty":          "; only a comment\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePatch(strings.NewReader(text), "lab.test."); err == nil {
				t.Fatal("expected parse failure")
			}
		})
	}
}

func TestApplyPatchReportsMissingDeleteAndCNAMEConflict(t *testing.T) {
	base, _ := NewSnapshot("lab.test.", 9, mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400}))

	missing, err := ParsePatch(strings.NewReader(`
ADD new.lab.test. 600 IN A 127.0.0.40
DEL nope.lab.test. 600 IN A 127.0.0.41
`), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyPatch(base, missing, Limits{MinTTL: 30, MaxTTL: 86400})
	if err == nil {
		t.Fatal("patch with nonexistent DEL must fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "DEL nope.lab.test. 600 IN A 127.0.0.41") ||
		!strings.Contains(msg, "record does not exist") {
		t.Fatalf("error must identify DEL operation: %v", err)
	}
	if strings.Contains(msg, "ADD new.lab.test.") {
		t.Fatalf("failed patch must not publish or report partial ADD: %v", err)
	}

	cname, err := ParsePatch(strings.NewReader(`ADD www.lab.test. 600 IN CNAME host.lab.test.`), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyPatch(base, cname, Limits{MinTTL: 30, MaxTTL: 86400})
	if err == nil {
		t.Fatal("CNAME conflict must fail")
	}
	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("want *OperationError, got %T: %v", err, err)
	}
	if opErr.Op.Action != "ADD" || opErr.Op.RR.Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("operation error points at %#v", opErr.Op)
	}
	if !strings.Contains(err.Error(), "candidate") ||
		!strings.Contains(err.Error(), "www.lab.test. 3600 IN A 127.0.0.20") {
		t.Fatalf("conflict error must list the candidate records: %v", err)
	}
	if !strings.Contains(err.Error(), "www.lab.test. 600 IN CNAME host.lab.test.") {
		t.Fatalf("conflict error must name the ADD operation: %v", err)
	}

	// Failed candidate construction leaves base untouched.
	if as, found := base.Lookup("new.lab.test.", dns.TypeA); found || len(as) != 0 {
		t.Fatal("base snapshot was mutated")
	}
}

func TestApplyPatchTTLChangeProducesDELAndADD(t *testing.T) {
	base, _ := NewSnapshot("lab.test.", 3, mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400}))
	ops, err := ParsePatch(strings.NewReader(`
DEL www.lab.test. 3600 IN A 127.0.0.20
ADD www.lab.test. 60 IN A 127.0.0.20
`), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ApplyPatch(base, ops, Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	changes := Diff(base, candidate)
	if len(changes) != 2 {
		t.Fatalf("TTL-only replacement needs DEL+ADD, got %d: %#v", len(changes), changes)
	}
	if changes[0].Action != "DEL" || changes[0].RR.Header().Ttl != 3600 ||
		changes[1].Action != "ADD" || changes[1].RR.Header().Ttl != 60 {
		t.Fatalf("changes preserve old/new TTLs: %#v", changes)
	}
}
