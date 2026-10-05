package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

var patchLimits = zone.Limits{MinTTL: 30, MaxTTL: 86400}

func patchOps(t *testing.T, text string) []zone.PatchOp {
	t.Helper()
	ops, err := zone.ParsePatch(strings.NewReader(text), origin, patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

// One patch touches both an A and a TXT record; the published version is
// visible identically through the lookup (query) path and the full RR
// list (AXFR path) of the same snapshot.
func TestPublishPatchAddAAndTXT(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", patchLimits); err != nil {
		t.Fatal(err)
	}

	ops := patchOps(t, `
# one patch, two record types
ADD host2 3600 IN A 127.0.0.30
ADD www 3600 IN TXT "patch-txt"
`)
	res, err := s.PublishPatch(ctx, ops, "a+txt", patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 2 {
		t.Fatalf("patch serial = %d, want 2", res.Serial)
	}

	snap, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Serial != 2 || snap.SOA().Serial != 2 {
		t.Fatalf("current snapshot serial = %d (SOA %d), want 2", snap.Serial, snap.SOA().Serial)
	}

	// Query path: both new records answer.
	if as, found := snap.Lookup("host2.lab.test.", dns.TypeA); !found || len(as) != 1 ||
		as[0].(*dns.A).A.String() != "127.0.0.30" {
		t.Fatalf("host2 A lookup = %v found=%v", as, found)
	}
	ts, found := snap.Lookup("www.lab.test.", dns.TypeTXT)
	if !found || len(ts) != 1 || ts[0].(*dns.TXT).Txt[0] != "patch-txt" {
		t.Fatalf("www TXT lookup = %v found=%v", ts, found)
	}

	// AXFR path: the same snapshot's full RR list carries both records.
	var sawA, sawTXT bool
	for _, rr := range snap.RRs {
		switch {
		case rr.Header().Rrtype == dns.TypeA && rr.Header().Name == "host2.lab.test.":
			sawA = true
		case rr.Header().Rrtype == dns.TypeTXT && rr.Header().Name == "www.lab.test.":
			sawTXT = true
		}
	}
	if !sawA || !sawTXT {
		t.Fatalf("AXFR record set missing patch records: A=%v TXT=%v", sawA, sawTXT)
	}

	// The changelog for the patched version is exactly the two ADDs, so
	// IXFR clients converge to the same state.
	changes, err := s.LoadChanges(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("changelog has %d entries, want 2", len(changes))
	}
	for _, c := range changes {
		if c.Action != "ADD" {
			t.Fatalf("unexpected changelog action %s", c.Action)
		}
	}
}

// A failing patch reports the offending operation and publishes nothing:
// the serial does not move and no partial state is stored.
func TestPublishPatchFailuresDoNotMoveSerial(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", patchLimits); err != nil {
		t.Fatal(err)
	}

	// DEL of a record that does not exist (followed by a valid ADD that
	// must NOT be applied either).
	_, err := s.PublishPatch(ctx, patchOps(t, `
DEL nosuch 3600 IN A 127.0.0.99
ADD host2 3600 IN A 127.0.0.30
`), "del-missing", patchLimits)
	if err == nil || !strings.Contains(err.Error(), "DEL nosuch.lab.test. 3600 IN A 127.0.0.99") {
		t.Fatalf("DEL of missing record must name the operation, got: %v", err)
	}

	// ADD that would create a CNAME conflict (www holds A records).
	_, err = s.PublishPatch(ctx, patchOps(t,
		"ADD www 3600 IN CNAME other.lab.test.\n"), "cname-conflict", patchLimits)
	if err == nil || !strings.Contains(err.Error(), "ADD www.lab.test. 3600 IN CNAME other.lab.test.") ||
		!strings.Contains(err.Error(), "conflict") {
		t.Fatalf("CNAME conflict must name the operation, got: %v", err)
	}

	// ADD of a record that already exists.
	_, err = s.PublishPatch(ctx, patchOps(t,
		"ADD www 3600 IN A 127.0.0.20\n"), "dup", patchLimits)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate ADD must fail, got: %v", err)
	}

	// Nothing moved: serial still 1, exactly one version row, and the
	// would-be partial results (host2, CNAME) are absent.
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after failed patches serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1 (rolled back)", n, err)
	}
	snap, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := snap.Lookup("host2.lab.test.", dns.TypeA); found {
		t.Fatal("failed patch leaked a partial result (host2)")
	}
	if as, _ := snap.Lookup("www.lab.test.", dns.TypeCNAME); len(as) != 0 {
		t.Fatal("failed patch leaked a partial result (CNAME)")
	}
}

func TestPublishPatchRequiresBaseVersion(t *testing.T) {
	s := freshStore(t)
	_, err := s.PublishPatch(context.Background(), patchOps(t,
		"ADD host2 3600 IN A 127.0.0.30\n"), "no-base", patchLimits)
	if err == nil || !strings.Contains(err.Error(), "no published version") {
		t.Fatalf("patch without a base version must fail, got: %v", err)
	}
}

// After a patch release, a classic full-file publish keeps working and
// replaces the whole zone contents as before.
func TestFullPublishStillWorksAfterPatch(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", patchLimits); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishPatch(ctx, patchOps(t, `
ADD host2 3600 IN A 127.0.0.30
ADD www 3600 IN TXT "patch-txt"
`), "patch", patchLimits); err != nil {
		t.Fatal(err)
	}

	// Full-file publish of content(2): has host2, no TXT at www.
	res, err := s.Publish(ctx, parse(t, content(2)), "back-to-file", patchLimits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 3 {
		t.Fatalf("full publish after patch serial = %d, want 3", res.Serial)
	}
	snap, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := snap.Lookup("host2.lab.test.", dns.TypeA); !found {
		t.Fatal("host2 from the full file missing")
	}
	if ts, _ := snap.Lookup("www.lab.test.", dns.TypeTXT); len(ts) != 0 {
		t.Fatal("full publish must replace wholesale: patch-added TXT still present")
	}

	// The changelog of version 3 records the removal of the patch TXT.
	changes, err := s.LoadChanges(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	var sawDelTXT bool
	for _, c := range changes {
		if c.Action == "DEL" && c.RR.Header().Rrtype == dns.TypeTXT {
			sawDelTXT = true
		}
	}
	if !sawDelTXT {
		t.Fatal("changelog for v3 must record the TXT removal")
	}
}

// Patches and full-file publishes share one serialized transaction path:
// mixed concurrent publishers produce consecutive serials with no gaps
// and no lost versions.
func TestConcurrentPatchAndPublishSerialize(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", patchLimits); err != nil {
		t.Fatal(err)
	}

	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Publish(ctx, parse(t, content(i)),
				fmt.Sprintf("full-%d", i), patchLimits); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			ops := patchOps(t, fmt.Sprintf("ADD hostp%d 3600 IN A 127.0.0.9%d\n", i, i))
			if _, err := s.PublishPatch(ctx, ops,
				fmt.Sprintf("patch-%d", i), patchLimits); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent mixed publish: %v", err)
	}

	serial, err := s.CurrentSerial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if serial != 1+2*n {
		t.Fatalf("serial after mixed publishes = %d, want %d (gap or loss)", serial, 1+2*n)
	}
	for v := uint32(1); v <= serial; v++ {
		snap, err := s.LoadSnapshot(ctx, v)
		if err != nil {
			t.Fatalf("version %d missing: %v", v, err)
		}
		if snap.SOA().Serial != v {
			t.Fatalf("version %d snapshot SOA serial %d", v, snap.SOA().Serial)
		}
	}
}
