package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// testDatabaseURL returns the database used by integration tests. Set
// DNSZONE_TEST_DATABASE to point at it; tests skip when unreachable so
// plain `go test ./...` stays self-contained.
func testDatabaseURL() string {
	if u := os.Getenv("DNSZONE_TEST_DATABASE"); u != "" {
		return u
	}
	return "postgres://dnsadmin@127.0.0.1:55432/dnszone_test?sslmode=disable&connect_timeout=2"
}

const origin = "lab.test."

func freshStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := New(ctx, testDatabaseURL(), origin)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	// Clean slate for deterministic serials.
	if _, err := s.pool.Exec(ctx, `TRUNCATE zone_changes, zone_records, zone_versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE zone_meta SET current_serial=0, origin=$1 WHERE id=1`, origin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func parse(t *testing.T, text string) []dns.RR {
	t.Helper()
	rrs, err := zone.Parse(strings.NewReader(text), origin,
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	return rrs
}

func TestPublishAndLoad(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	rrs := parse(t, `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
`)
	res, err := s.Publish(ctx, rrs, "first", zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 1 {
		t.Fatalf("first serial = %d, want 1", res.Serial)
	}
	snap, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Serial != 1 {
		t.Fatalf("loaded serial = %d", snap.Serial)
	}
	as, found := snap.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 1 {
		t.Fatalf("loaded snapshot content wrong: %v", as)
	}
	// SOA serial stored on the version must equal the snapshot serial.
	if snap.SOA().Serial != 1 {
		t.Fatal("SOA serial mismatch")
	}
}

func TestInvalidPublishIsAtomicNoOp(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}

	// Build RRs directly (bypassing parser validation) so that the
	// transaction's own defense rejects them and rolls everything back.
	mustRR := func(text string) dns.RR {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	soa := snapSOA(t, s, 1)
	outOfZone := []dns.RR{
		soa,
		mustRR("lab.test. 3600 IN NS ns1.lab.test."),
		mustRR("ns1.lab.test. 3600 IN A 127.0.0.10"),
		mustRR("host.other.test. 3600 IN A 1.2.3.4"),
	}
	if _, err := s.Publish(ctx, outOfZone, "bad-owner",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
		t.Fatal("out-of-zone publish must fail")
	}

	lowTTL := []dns.RR{
		soa,
		mustRR("lab.test. 3600 IN NS ns1.lab.test."),
		mustRR("ns1.lab.test. 5 IN A 127.0.0.10"),
	}
	if _, err := s.Publish(ctx, lowTTL, "bad-ttl",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
		t.Fatal("TTL below bound publish must fail")
	}

	// Nothing moved: serial still 1 and exactly one version row.
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after failed publishes serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1 (rolled back)", n, err)
	}
}

// snapSOA returns a copy of version v's SOA RR so tests can assemble raw
// record sets for negative Publish paths.
func snapSOA(t *testing.T, s *Store, v uint32) dns.RR {
	t.Helper()
	snap, err := s.LoadSnapshot(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	return snap.SOA()
}

func TestConcurrentPublishSerializes(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Publish(ctx, parse(t, content(i)),
				fmt.Sprintf("p%d", i), zone.Limits{MinTTL: 30, MaxTTL: 86400})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent publish: %v", err)
	}

	serial, err := s.CurrentSerial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if serial != n {
		t.Fatalf("serial after %d concurrent publishes = %d (gap or loss)", n, serial)
	}

	// Each version 1..n exists and its snapshot is internally complete:
	// SOA serial always agrees with the version number.
	for v := uint32(1); v <= n; v++ {
		snap, err := s.LoadSnapshot(ctx, v)
		if err != nil {
			t.Fatalf("version %d missing: %v", v, err)
		}
		if snap.SOA().Serial != v {
			t.Fatalf("version %d snapshot SOA serial %d", v, snap.SOA().Serial)
		}
	}
}

func TestChangelogDrivesIXFRDelta(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, parse(t, content(2)), "v2",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}
	changes, err := s.LoadChanges(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	var adds, dels int
	var sawSOA bool
	for _, c := range changes {
		switch c.Action {
		case "ADD":
			adds++
		case "DEL":
			dels++
		}
		if c.RR.Header().Rrtype == dns.TypeSOA {
			sawSOA = true
		}
	}
	// content(2) differs from content(0) by adding host2 only.
	if adds != 1 || dels != 0 {
		t.Fatalf("changelog adds=%d dels=%d, want 1/0", adds, dels)
	}
	if sawSOA {
		t.Fatal("SOA must not appear in record deltas")
	}
}

func TestPatchPublishesAndFullPublishStillWorks(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}

	ops, err := zone.ParsePatch(strings.NewReader(`
DEL www.lab.test. 3600 IN A 127.0.0.21
ADD www.lab.test. 3600 IN TXT "patched in serial 2"
ADD host2.lab.test. 3600 IN A 127.0.0.30
`), origin)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.PublishPatch(ctx, ops, "record patch", lim)
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
	if got, _ := snap.Lookup("www.lab.test.", dns.TypeA); len(got) != 1 {
		t.Fatalf("www A after patch = %d records", len(got))
	}
	if got, _ := snap.Lookup("www.lab.test.", dns.TypeTXT); len(got) != 1 {
		t.Fatalf("www TXT after patch = %d records", len(got))
	}
	if got, found := snap.Lookup("host2.lab.test.", dns.TypeA); !found || len(got) != 1 {
		t.Fatal("patch ADD is queryable in the published snapshot")
	}
	changes, err := s.LoadChanges(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	var adds, dels int
	for _, c := range changes {
		switch c.Action {
		case "ADD":
			adds++
		case "DEL":
			dels++
		}
	}
	if adds != 2 || dels != 1 {
		t.Fatalf("patch changelog adds=%d dels=%d, want 2/1", adds, dels)
	}

	// A later full master-file publish follows the same normal path and
	// becomes serial 3.
	if _, err := s.Publish(ctx, parse(t, content(2)), "full v3", lim); err != nil {
		t.Fatal(err)
	}
	snap, err = s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Serial != 3 || snap.SOA().Serial != 3 {
		t.Fatalf("full publish after patch serial = %d", snap.Serial)
	}
}

func TestFailedPatchDoesNotIncreaseSerial(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}

	ops, err := zone.ParsePatch(strings.NewReader(`
ADD host2.lab.test. 3600 IN CNAME www.lab.test.
DEL missing.lab.test. 3600 IN A 127.0.0.99
`), origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishPatch(ctx, ops, "bad patch", lim); err == nil {
		t.Fatal("invalid patch must fail")
	}
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after failed patch serial=%d err=%v, want 1", serial, err)
	}
	cnameOps, err := zone.ParsePatch(strings.NewReader(`ADD www.lab.test. 3600 IN CNAME host2.lab.test.`), origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishPatch(ctx, cnameOps, "cname conflict", lim); err == nil {
		t.Fatal("CNAME conflict patch must fail")
	}
	serial, err = s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after conflict patch serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1", n, err)
	}
	ghostChanges, err := s.LoadChanges(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ghostChanges) != 0 {
		t.Fatalf("failed patch inserted a serial-2 changelog: %#v", ghostChanges)
	}

	// Also reject before opening the publication path when no version exists.
	s2 := freshStore(t)
	if _, err := s2.PublishPatch(ctx, ops, "before first", lim); err == nil {
		t.Fatal("patch against no current version must fail")
	}
	if serial, err := s2.CurrentSerial(ctx); err != nil || serial != 0 {
		t.Fatalf("baseless patch serial=%d err=%v, want 0", serial, err)
	}
}

// content returns a zone text where variant adds `variant` extra host
// records, giving each publish a distinct-but-related RR set.
func content(variant int) string {
	base := `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
`
	if variant == 2 {
		base += "host2 IN A 127.0.0.30\n"
	}
	return base
}
