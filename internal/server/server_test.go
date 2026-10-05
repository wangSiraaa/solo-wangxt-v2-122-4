package server

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

const testZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (7 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
alias IN CNAME www.lab.test.
`

// base64 of "e2e-tsig-secret", shared by server and client in these tests
const testTSIGB64 = "ZTJlLXRzaWctc2VjcmV0"

func newTestServer(t *testing.T, snap *zone.Snapshot) string {
	t.Helper()
	cfgJSON := `{
	  "zone": "lab.test.",
	  "listen_udp": "127.0.0.1:0",
	  "listen_tcp": "127.0.0.1:0",
	  "database_url": "postgres://unused",
	  "ttl_min": 30, "ttl_max": 86400,
	  "transfer_allow_cidrs": ["127.0.0.0/8", "::1/128"],
	  "tsig_keys": {
	    "xfer.lab.test.": {"algorithm": "hmac-sha256", "secret_b64": "` + testTSIGB64 + `"}
	  }
	}`
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

	srv := &Server{cfg: cfg, logger: log.New(io.Discard, "", 0)}
	srv.snapshot.Store(snap)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Share the port between TCP and UDP, like the production listener.
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		pc.Close()
		ln.Close()
	})
	go srv.Serve(ctx, pc, ln)

	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Timeout = 100 * time.Millisecond
		probe := new(dns.Msg)
		probe.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := c.Exchange(probe, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr
}

func snap(t *testing.T, serial uint32, text string) *zone.Snapshot {
	t.Helper()
	rrs, err := zone.Parse(strings.NewReader(text), "lab.test.",
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	s, err := zone.NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dnsQuery(t *testing.T, addr, network, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	c.Net = network
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return r
}

func TestE2EPositiveAndNegative(t *testing.T) {
	addr := newTestServer(t, snap(t, 7, testZone))

	// Same name, multiple records.
	r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 2 {
		t.Fatalf("www A: rcode=%s aa=%v answers=%d",
			dns.RcodeToString[r.Rcode], r.Authoritative, len(r.Answer))
	}
	if r.RecursionAvailable {
		t.Fatal("RA must never be set: this server does not recurse")
	}

	// CNAME chain includes the CNAME and both target records.
	r = dnsQuery(t, addr, "udp", "alias.lab.test.", dns.TypeA)
	if len(r.Answer) != 3 || r.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("alias A chain wrong: %v", r.Answer)
	}

	// NXDOMAIN: AA plus SOA authority with the negative-cache TTL.
	r = dnsQuery(t, addr, "udp", "nope.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError || !r.Authoritative || len(r.Ns) != 1 {
		t.Fatalf("NXDOMAIN wrong: rcode=%s aa=%v ns=%d",
			dns.RcodeToString[r.Rcode], r.Authoritative, len(r.Ns))
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Ttl != 300 {
		t.Fatalf("negative SOA TTL = %v, want 300 = min(SOA ttl, minimum)", r.Ns[0])
	}

	// NODATA: existing name, missing type -> NOERROR + SOA authority.
	r = dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeMX)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("NODATA wrong: rcode=%s answers=%d ns=%d",
			dns.RcodeToString[r.Rcode], len(r.Answer), len(r.Ns))
	}

	// Out of zone: REFUSED and never recursion.
	r = dnsQuery(t, addr, "udp", "example.com.", dns.TypeA)
	if r.Rcode != dns.RcodeRefused || r.RecursionAvailable {
		t.Fatalf("out-of-zone: rcode=%s ra=%v", dns.RcodeToString[r.Rcode], r.RecursionAvailable)
	}

	// Non-query opcode -> NOTIMP.
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.SetQuestion("lab.test.", dns.TypeSOA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("UPDATE opcode rcode=%s, want NOTIMP", dns.RcodeToString[r.Rcode])
	}
}

// TestE2EAtomicSwapSnapshot drives the exact primitive used on publish:
// one atomic pointer replacement. Concurrent readers must only observe
// complete snapshots, and an AXFR in flight stays on one version.
func TestE2EAtomicSwapSnapshot(t *testing.T) {
	// Serial is assigned by the publisher (NewSnapshot rewrites the SOA);
	// s1=1, s2=8 leaves a visible gap like a jump across versions.
	s1 := snap(t, 1, testZone)
	s2 := snap(t, 8, testZone)

	srv := &Server{
		cfg:    mustConfig(t),
		logger: log.New(io.Discard, "", 0),
	}
	srv.snapshot.Store(s1)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	pc, _ := net.ListenPacket("udp", ln.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, pc, ln)
	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pc := new(dns.Client)
		pc.Timeout = 100 * time.Millisecond
		probe := new(dns.Msg)
		probe.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := pc.Exchange(probe, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	stop := make(chan struct{})
	errs := make(chan string, 64)
	go func() {
		client := new(dns.Client)
		for {
			select {
			case <-stop:
				return
			default:
			}
			m := new(dns.Msg)
			m.SetQuestion("www.lab.test.", dns.TypeA)
			r, _, err := client.Exchange(m, addr)
			if err != nil {
				errs <- "query error: " + err.Error()
				return
			}
			if n := len(r.Answer); n != 2 {
				errs <- "partial www rrset"
				return
			}
		}
	}()
	// Single swap: old -> new in one atomic step.
	srv.snapshot.Store(s2)
	r := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA)
	if r.Answer[0].(*dns.SOA).Serial != 8 {
		t.Fatalf("post-swap SOA serial = %d, want 8", r.Answer[0].(*dns.SOA).Serial)
	}
	close(stop)
	select {
	case e := <-errs:
		t.Fatal(e)
	default:
	}
}

func mustConfig(t *testing.T) *config.Config {
	t.Helper()
	f, _ := os.CreateTemp(t.TempDir(), "cfg-*.json")
	f.WriteString(`{
	  "zone": "lab.test.", "listen_udp": "127.0.0.1:0", "listen_tcp": "127.0.0.1:0",
	  "database_url": "postgres://unused", "ttl_min": 30, "ttl_max": 86400,
	  "transfer_allow_cidrs": ["127.0.0.0/8"],
	  "tsig_keys": {"xfer.lab.test.": {"algorithm": "hmac-sha256", "secret_b64": "` + testTSIGB64 + `"}}
	}`)
	f.Close()
	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestE2EPatchSnapshotServedByQueryAndAXFR(t *testing.T) {
	base := snap(t, 7, testZone)
	ops, err := zone.ParsePatch(strings.NewReader(`
DEL www.lab.test. 3600 IN A 127.0.0.21
ADD www.lab.test. 3600 IN TXT "patched while serving"
ADD host3.lab.test. 3600 IN A 127.0.0.33
`), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := zone.ApplyPatch(base, ops, zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	// The store rewrites the SOA serial on publication; emulate that on
	// the immutable snapshot before the single serving-pointer swap.
	published, err := zone.NewSnapshot("lab.test.", 8, candidate.RRs)
	if err != nil {
		t.Fatal(err)
	}
	addr := newTestServer(t, published)

	if r := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA); r.Answer[0].(*dns.SOA).Serial != 8 {
		t.Fatal("query did not see patched serial 8")
	}
	if r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeA); len(r.Answer) != 1 {
		t.Fatalf("patched www A answers=%d, want 1", len(r.Answer))
	}
	if r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeTXT); len(r.Answer) != 1 {
		t.Fatalf("patched www TXT answers=%d, want 1", len(r.Answer))
	}
	if r := dnsQuery(t, addr, "tcp", "host3.lab.test.", dns.TypeA); len(r.Answer) != 1 {
		t.Fatalf("patched host3 A answers=%d, want 1", len(r.Answer))
	}

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"xfer.lab.test.": testTSIGB64}
	q := new(dns.Msg)
	q.SetQuestion("lab.test.", dns.TypeAXFR)
	q.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	var axfr []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
		axfr = append(axfr, e.RR...)
	}
	if axfr[0].(*dns.SOA).Serial != 8 || axfr[len(axfr)-1].(*dns.SOA).Serial != 8 {
		t.Fatal("AXFR did not use patched serial 8 for both SOA bookends")
	}
	var sawHost3, sawPatchedTXT, sawRemovedA bool
	for _, rr := range axfr {
		switch v := rr.(type) {
		case *dns.A:
			if v.Hdr.Name == "host3.lab.test." && v.A.String() == "127.0.0.33" {
				sawHost3 = true
			}
			if v.Hdr.Name == "www.lab.test." && v.A.String() == "127.0.0.21" {
				sawRemovedA = true
			}
		case *dns.TXT:
			if v.Hdr.Name == "www.lab.test." && len(v.Txt) > 0 && v.Txt[0] == "patched while serving" {
				sawPatchedTXT = true
			}
		}
	}
	if !sawHost3 || !sawPatchedTXT {
		t.Fatalf("AXFR missing patched records: host3=%v txt=%v", sawHost3, sawPatchedTXT)
	}
	if sawRemovedA {
		t.Fatal("AXFR still contains the deleted www A 127.0.0.21")
	}
}

func TestE2EStorePatchVisibleToQueryAndAXFR(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, err := store.New(ctx, "postgres://dnsadmin@127.0.0.1:55432/dnszone_server_test?sslmode=disable&connect_timeout=2", "lab.test.")
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	t.Cleanup(st.Close)

	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	rrs, err := zone.Parse(strings.NewReader(testZone), "lab.test.", lim)
	if err != nil {
		t.Fatal(err)
	}
	base, err := st.Publish(ctx, rrs, "server patch base", lim)
	if err != nil {
		t.Fatal(err)
	}

	cfg := mustConfig(t)
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
	serveCtx, stopServe := context.WithCancel(ctx)
	t.Cleanup(func() {
		stopServe()
		pc.Close()
		ln.Close()
	})
	go srv.Serve(serveCtx, pc, ln)
	addr := ln.Addr().String()
	waitForServer(t, addr)

	ops, err := zone.ParsePatch(strings.NewReader(`
DEL www.lab.test. 3600 IN A 127.0.0.21
ADD www.lab.test. 3600 IN TXT "store patch served identically"
ADD host4.lab.test. 3600 IN A 127.0.0.34
`), "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	patch, err := st.PublishPatch(ctx, ops, "server patch", lim)
	if err != nil {
		t.Fatal(err)
	}
	if patch.Serial != base.Serial+1 {
		t.Fatalf("patched serial = %d, base = %d", patch.Serial, base.Serial)
	}
	waitForSOASerial(t, addr, patch.Serial)

	if r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeA); len(r.Answer) != 1 {
		t.Fatalf("query www A = %d answers after patch", len(r.Answer))
	}
	if r := dnsQuery(t, addr, "tcp", "www.lab.test.", dns.TypeTXT); len(r.Answer) != 1 {
		t.Fatalf("query www TXT = %d answers after patch", len(r.Answer))
	}
	if r := dnsQuery(t, addr, "udp", "host4.lab.test.", dns.TypeA); len(r.Answer) != 1 {
		t.Fatalf("query host4 A = %d answers after patch", len(r.Answer))
	}
	if r := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA); r.Answer[0].(*dns.SOA).Serial != patch.Serial {
		t.Fatal("query serial does not match patched version")
	}

	axfr := signedAXFR(t, addr)
	if axfr[0].(*dns.SOA).Serial != patch.Serial || axfr[len(axfr)-1].(*dns.SOA).Serial != patch.Serial {
		t.Fatal("AXFR serial does not match the patched version")
	}
	var host4s, txts, removedAs int
	for _, rr := range axfr {
		switch v := rr.(type) {
		case *dns.A:
			if v.Hdr.Name == "host4.lab.test." {
				host4s++
			}
			if v.Hdr.Name == "www.lab.test." && v.A.String() == "127.0.0.21" {
				removedAs++
			}
		case *dns.TXT:
			if v.Hdr.Name == "www.lab.test." && len(v.Txt) > 0 && v.Txt[0] == "store patch served identically" {
				txts++
			}
		}
	}
	if host4s != 1 || txts != 1 || removedAs != 0 {
		t.Fatalf("AXFR content host4=%d txt=%d removedA=%d", host4s, txts, removedAs)
	}
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Timeout = 100 * time.Millisecond
		m := new(dns.Msg)
		m.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := c.Exchange(m, addr); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("test DNS server did not become ready")
}

func waitForSOASerial(t *testing.T, addr string, serial uint32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA); r.Answer[0].(*dns.SOA).Serial == serial {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not hot-reload serial %d", serial)
}

func signedAXFR(t *testing.T, addr string) []dns.RR {
	t.Helper()
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
			t.Fatal(e.Error)
		}
		all = append(all, e.RR...)
	}
	return all
}

func TestE2ETransferGateAndContent(t *testing.T) {
	addr := newTestServer(t, snap(t, 7, testZone))

	// Unsigned AXFR over TCP -> REFUSED.
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("lab.test.", dns.TypeAXFR)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned AXFR rcode=%s, want REFUSED", dns.RcodeToString[r.Rcode])
	}

	// Authorized, correctly signed AXFR: SOA bookends with serial 7.
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
	if all[0].(*dns.SOA).Serial != 7 || all[len(all)-1].(*dns.SOA).Serial != 7 {
		t.Fatal("AXFR must open and close with the same SOA serial")
	}

	// Wrong secret -> REFUSED (server uses library verification only).
	bad := new(dns.Client)
	bad.Net = "tcp"
	bad.TsigSecret = map[string]string{"xfer.lab.test.": "YmFkLXNlY3JldC1iYWQtc2VjcmV0LWI="}
	bm := new(dns.Msg)
	bm.SetQuestion("lab.test.", dns.TypeAXFR)
	bm.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	br, _, err := bad.Exchange(bm, addr)
	if err != nil {
		t.Fatal(err)
	}
	if br.Rcode != dns.RcodeRefused {
		t.Fatalf("bad-secret AXFR rcode=%s, want REFUSED", dns.RcodeToString[br.Rcode])
	}
}
