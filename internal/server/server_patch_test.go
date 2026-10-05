package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

// serverTestDatabase returns a dedicated database for server integration
// tests (created on demand) so they never share tables with the store
// package tests, which truncate freely. Skips when PostgreSQL is
// unreachable, mirroring the store test convention.
func serverTestDatabase(t *testing.T) string {
	t.Helper()
	base := os.Getenv("DNSZONE_TEST_DATABASE")
	if base == "" {
		base = "postgres://dnsadmin@127.0.0.1:55432/dnszone_test?sslmode=disable&connect_timeout=2"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	defer conn.Close(context.Background())

	const db = "dnszone_server_test"
	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, db).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + db
	return u.String()
}

// End-to-end over real sockets and a real PostgreSQL: a record patch that
// changes A and TXT in one release is picked up by the running server,
// and afterwards the query path and AXFR serve the same new version.
func TestE2EPatchPublishQueryAndAXFR(t *testing.T) {
	dbURL := serverTestDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, dbURL, "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	// Cancel first so the server's LISTEN connection is released back to
	// the pool before Close waits for it.
	defer func() {
		cancel()
		st.Close()
	}()

	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	rrs, err := zone.Parse(strings.NewReader(testZone), "lab.test.", lim)
	if err != nil {
		t.Fatal(err)
	}
	base, err := st.Publish(ctx, rrs, "e2e-base", lim)
	if err != nil {
		t.Fatal(err)
	}

	cfgJSON := fmt.Sprintf(`{
	  "zone": "lab.test.",
	  "listen_udp": "127.0.0.1:0",
	  "listen_tcp": "127.0.0.1:0",
	  "database_url": %q,
	  "ttl_min": 30, "ttl_max": 86400,
	  "transfer_allow_cidrs": ["127.0.0.0/8"],
	  "tsig_keys": {
	    "xfer.lab.test.": {"algorithm": "hmac-sha256", "secret_b64": %q}
	  }
	}`, dbURL, testTSIGB64)
	f, err := os.CreateTemp(t.TempDir(), "cfg-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(cfgJSON); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(ctx, cfg, st, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		pc.Close()
		ln.Close()
	})
	go srv.Serve(ctx, pc, ln)
	addr := ln.Addr().String()

	// Wait until the server answers the base version.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Timeout = 100 * time.Millisecond
		probe := new(dns.Msg)
		probe.SetQuestion("lab.test.", dns.TypeSOA)
		if r, _, err := c.Exchange(probe, addr); err == nil && len(r.Answer) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// One patch, two record types: an A addition and a TXT addition.
	ops, err := zone.ParsePatch(strings.NewReader(`
ADD host2 3600 IN A 127.0.0.30
ADD www 3600 IN TXT "e2e-patch"
`), "lab.test.", lim)
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.PublishPatch(ctx, ops, "e2e-patch", lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != base.Serial+1 {
		t.Fatalf("patch serial = %d, want %d", res.Serial, base.Serial+1)
	}

	// The server reloads via LISTEN/NOTIFY; poll until the new version
	// answers queries.
	deadline = time.Now().Add(3 * time.Second)
	for {
		r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeTXT)
		if len(r.Answer) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not pick up the patched version in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Query path: both patched records answer from the new serial.
	r := dnsQuery(t, addr, "udp", "host2.lab.test.", dns.TypeA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "127.0.0.30" {
		t.Fatalf("host2 A answer = %v", r.Answer)
	}
	r = dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeTXT)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != "e2e-patch" {
		t.Fatalf("www TXT answer = %v", r.Answer)
	}
	querySerial := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA).
		Answer[0].(*dns.SOA).Serial
	if querySerial != res.Serial {
		t.Fatalf("query SOA serial = %d, want %d", querySerial, res.Serial)
	}

	// AXFR path: the transfer streams the same version the queries see.
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"xfer.lab.test.": testTSIGB64}
	q := new(dns.Msg)
	q.SetQuestion("lab.test.", dns.TypeAXFR)
	q.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	var all []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("envelope: %v", e.Error)
		}
		all = append(all, e.RR...)
	}
	if len(all) < 3 {
		t.Fatalf("AXFR too short: %d RRs", len(all))
	}
	first, last := all[0].(*dns.SOA).Serial, all[len(all)-1].(*dns.SOA).Serial
	if first != res.Serial || last != res.Serial {
		t.Fatalf("AXFR SOA bookends %d..%d, want %d (query serial %d)",
			first, last, res.Serial, querySerial)
	}
	var sawA, sawTXT bool
	for _, rr := range all {
		switch {
		case rr.Header().Rrtype == dns.TypeA && rr.Header().Name == "host2.lab.test.":
			sawA = true
		case rr.Header().Rrtype == dns.TypeTXT && rr.Header().Name == "www.lab.test.":
			sawTXT = true
		}
	}
	if !sawA || !sawTXT {
		t.Fatalf("AXFR missing patch records: A=%v TXT=%v", sawA, sawTXT)
	}
}
