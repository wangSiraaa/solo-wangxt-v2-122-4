package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const patchTestZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
@ IN NS ns2.lab.test.
ns1 IN A 127.0.0.10
ns2 IN A 127.0.0.11
www IN A 127.0.0.20
www IN TXT "hello"
alias IN CNAME www.lab.test.
`

var patchLimits = Limits{MinTTL: 30, MaxTTL: 86400}

func patchSnap(t *testing.T) *Snapshot {
	t.Helper()
	rrs, err := Parse(strings.NewReader(patchTestZone), "lab.test.", patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSnapshot("lab.test.", 1, rrs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func patchOps(t *testing.T, text string) []PatchOp {
	t.Helper()
	ops, err := ParsePatch(strings.NewReader(text), "lab.test.", patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

func TestParsePatchOK(t *testing.T) {
	ops, err := ParsePatch(strings.NewReader(`
# a comment
; another comment

ADD host2 3600 IN A 127.0.0.30
add www 300 IN TXT "a b"   ; trailing comment
DEL @ 3600 IN A 127.0.0.5
`), "lab.test.", patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 3 {
		t.Fatalf("parsed %d ops, want 3", len(ops))
	}
	if ops[0].Action != "ADD" || ops[0].RR.Header().Name != "host2.lab.test." ||
		ops[0].RR.Header().Ttl != 3600 {
		t.Fatalf("op 1 wrong: %+v", ops[0])
	}
	// Lowercase action is accepted and normalized.
	if ops[1].Action != "ADD" || ops[1].RR.Header().Rrtype != dns.TypeTXT {
		t.Fatalf("op 2 wrong: %+v", ops[1])
	}
	// "@" resolves to the origin.
	if ops[2].Action != "DEL" || ops[2].RR.Header().Name != "lab.test." {
		t.Fatalf("op 3 wrong: %+v", ops[2])
	}
}

func TestParsePatchRejectsBadInput(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"bad action", "UPD www 3600 IN A 127.0.0.1\n", "action must be ADD or DEL"},
		{"missing record", "ADD\n", "requires a full record"},
		{"missing ttl", "ADD www IN A 127.0.0.1\n", "explicit TTL"},
		{"soa", "ADD @ 3600 IN SOA ns1.lab.test. admin.lab.test. (2 7200 3600 1209600 300)\n", "SOA cannot be patched"},
		{"out of zone", "ADD host.other.test. 3600 IN A 127.0.0.1\n", "outside zone"},
		{"ttl below min", "ADD www 5 IN A 127.0.0.1\n", "below minimum"},
		{"ttl above max", "ADD www 90000 IN A 127.0.0.1\n", "above maximum"},
		{"unsupported type", "ADD www 3600 IN DNSKEY 256 3 8 AwEAAa==\n", "not supported"},
		{"garbage rdata", "ADD www 3600 IN A not-an-ip\n", "line 1"},
		{"no operations", "# only a comment\n\n", "no operations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePatch(strings.NewReader(tc.text), "lab.test.", patchLimits)
			if err == nil {
				t.Fatalf("input %q: expected error", tc.text)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("input %q: error %q does not mention %q", tc.text, err, tc.want)
			}
		})
	}
}

func TestApplyPatchAddAndDel(t *testing.T) {
	snap := patchSnap(t)
	before := len(snap.RRs)

	ops := patchOps(t, `
ADD host2 3600 IN A 127.0.0.30
ADD www 3600 IN TXT "patched"
DEL www 3600 IN TXT "hello"
`)
	candidate, err := ApplyPatch(snap, ops)
	if err != nil {
		t.Fatal(err)
	}

	next, err := NewSnapshot("lab.test.", 2, candidate)
	if err != nil {
		t.Fatalf("candidate must be a valid zone: %v", err)
	}
	if as, found := next.Lookup("host2.lab.test.", dns.TypeA); !found || len(as) != 1 {
		t.Fatalf("host2 A missing from candidate: %v", as)
	}
	txts, found := next.Lookup("www.lab.test.", dns.TypeTXT)
	if !found || len(txts) != 1 {
		t.Fatalf("www TXT set wrong: %v", txts)
	}
	if got := txts[0].(*dns.TXT).Txt[0]; got != "patched" {
		t.Fatalf("www TXT = %q, want %q", got, "patched")
	}

	// The source snapshot is immutable: a patch never edits it in place.
	if len(snap.RRs) != before {
		t.Fatalf("source snapshot mutated: %d -> want %d records", len(snap.RRs), before)
	}
	if _, found := snap.Lookup("host2.lab.test.", dns.TypeA); found {
		t.Fatal("source snapshot gained host2")
	}
}

func TestApplyPatchDelMissingReportsOperation(t *testing.T) {
	snap := patchSnap(t)

	// Never existed.
	ops := patchOps(t, "DEL nosuch 3600 IN A 127.0.0.99\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "DEL nosuch.lab.test. 3600 IN A 127.0.0.99") ||
		!strings.Contains(err.Error(), "no such record") {
		t.Fatalf("DEL of missing record must name the operation, got: %v", err)
	}

	// Exists, but with a different TTL: TTL is part of the record identity.
	ops = patchOps(t, "DEL www 300 IN A 127.0.0.20\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "DEL www.lab.test. 300 IN A 127.0.0.20") {
		t.Fatalf("DEL with wrong TTL must fail and name the operation, got: %v", err)
	}
}

func TestApplyPatchCNAMEConflictReportsOperation(t *testing.T) {
	snap := patchSnap(t)

	// Adding a CNAME where an A record lives.
	ops := patchOps(t, "ADD www 3600 IN CNAME other.lab.test.\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "ADD www.lab.test. 3600 IN CNAME other.lab.test.") ||
		!strings.Contains(err.Error(), "conflicts with existing A") {
		t.Fatalf("CNAME-vs-A conflict must name the operation, got: %v", err)
	}

	// Adding data where a CNAME lives.
	ops = patchOps(t, "ADD alias 3600 IN A 127.0.0.50\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "ADD alias.lab.test. 3600 IN A 127.0.0.50") ||
		!strings.Contains(err.Error(), "existing CNAME") {
		t.Fatalf("A-vs-CNAME conflict must name the operation, got: %v", err)
	}

	// CNAME at the apex.
	ops = patchOps(t, "ADD @ 3600 IN CNAME other.lab.test.\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "apex") {
		t.Fatalf("apex CNAME must be rejected, got: %v", err)
	}

	// But replacing a CNAME with data in one patch is fine: DEL first.
	ops = patchOps(t, `
DEL alias 3600 IN CNAME www.lab.test.
ADD alias 3600 IN A 127.0.0.50
`)
	candidate, err := ApplyPatch(snap, ops)
	if err != nil {
		t.Fatalf("DEL+ADD at one name must succeed: %v", err)
	}
	next, err := NewSnapshot("lab.test.", 2, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if as, found := next.Lookup("alias.lab.test.", dns.TypeA); !found || len(as) != 1 {
		t.Fatalf("alias A missing after swap: %v", as)
	}
}

func TestApplyPatchDuplicateAdd(t *testing.T) {
	snap := patchSnap(t)
	ops := patchOps(t, "ADD www 3600 IN A 127.0.0.20\n")
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "ADD www.lab.test. 3600 IN A 127.0.0.20") ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate ADD must fail and name the operation, got: %v", err)
	}
}

func TestApplyPatchKeepsZoneInvariants(t *testing.T) {
	snap := patchSnap(t)

	// Deleting every apex NS leaves an invalid zone: the patch is rejected
	// as a whole even though each DEL names an existing record.
	ops := patchOps(t, `
DEL @ 3600 IN NS ns1.lab.test.
DEL @ 3600 IN NS ns2.lab.test.
`)
	if _, err := ApplyPatch(snap, ops); err == nil ||
		!strings.Contains(err.Error(), "resulting zone invalid") {
		t.Fatalf("patch breaking zone invariants must be rejected, got: %v", err)
	}

	// Empty patch.
	if _, err := ApplyPatch(snap, nil); err == nil {
		t.Fatal("empty patch must fail")
	}
}

func TestApplyPatchTTLChange(t *testing.T) {
	snap := patchSnap(t)
	// A TTL change is a DEL of the old record plus an ADD of the new one.
	ops := patchOps(t, `
DEL www 3600 IN A 127.0.0.20
ADD www 300 IN A 127.0.0.20
`)
	candidate, err := ApplyPatch(snap, ops)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewSnapshot("lab.test.", 2, candidate)
	if err != nil {
		t.Fatal(err)
	}
	as, found := next.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 1 || as[0].Header().Ttl != 300 {
		t.Fatalf("TTL change not applied: %v", as)
	}
}
