package zone

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

// PatchOp is one record-level addition or deletion applied to the
// current zone version to produce the next one.
type PatchOp struct {
	Action string // "ADD" or "DEL"
	RR     dns.RR // full record incl. TTL; owner normalized to lowercase FQDN
}

// ParsePatch reads a record patch: one operation per line,
//
//	ADD <owner> <ttl> IN <type> <rdata>
//	DEL <owner> <ttl> IN <type> <rdata>
//
// Blank lines and lines starting with '#' or ';' are ignored; a ';'
// also starts an end-of-line comment. Owners may be relative to the
// zone origin ("@", "www") or absolute. Every record must carry an
// explicit TTL inside lim, and the record itself must pass the same
// per-record checks as a zone-file entry (class IN, allowed type,
// in-zone owner). SOA operations are rejected: the SOA serial is
// assigned by the publisher on every release.
func ParsePatch(r io.Reader, origin string, lim Limits) ([]PatchOp, error) {
	origin = dns.Fqdn(origin)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var ops []PatchOp
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		i := strings.IndexAny(line, " \t")
		action, text := strings.ToUpper(line), ""
		if i >= 0 {
			action = strings.ToUpper(line[:i])
			text = strings.TrimSpace(line[i+1:])
		}
		if action != "ADD" && action != "DEL" {
			return nil, fmt.Errorf("patch line %d: action must be ADD or DEL, got %q", lineNo, line)
		}
		if text == "" {
			return nil, fmt.Errorf("patch line %d: %s requires a full record (owner TTL IN type rdata)", lineNo, action)
		}
		zp := dns.NewZoneParser(strings.NewReader(text+"\n"), origin, "patch")
		rr, ok := zp.Next()
		if !ok {
			if err := zp.Err(); err != nil {
				return nil, fmt.Errorf("patch line %d: %w", lineNo, err)
			}
			return nil, fmt.Errorf("patch line %d: cannot parse record %q", lineNo, text)
		}
		h := rr.Header()
		h.Name = strings.ToLower(dns.Fqdn(h.Name))
		if h.Ttl == 0 {
			// A missing TTL parses as 0; patches must state it explicitly
			// so ADD/DEL always names a complete, unambiguous record.
			return nil, fmt.Errorf("patch line %d: record %s %s must carry an explicit TTL",
				lineNo, h.Name, dns.TypeToString[h.Rrtype])
		}
		if h.Rrtype == dns.TypeSOA {
			return nil, fmt.Errorf("patch line %d: SOA cannot be patched; the serial is assigned at publish time", lineNo)
		}
		if err := validateRR(rr, origin, lim); err != nil {
			return nil, fmt.Errorf("patch line %d: %w", lineNo, err)
		}
		ops = append(ops, PatchOp{Action: action, RR: rr})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("patch read: %w", err)
	}
	if len(ops) == 0 {
		return nil, errors.New("patch contains no operations")
	}
	return ops, nil
}

// ApplyPatch applies ops to the current snapshot's records and returns
// the candidate RR set for the next version, sorted and validated. It is
// purely in-memory: cur is not modified and nothing is published. The
// first failing operation aborts the whole patch — there are no partial
// results:
//
//   - DEL names a record (owner, type, rdata and TTL) that must exist in
//     the current version; otherwise the error quotes the operation;
//   - ADD must not duplicate an existing record;
//   - ADD must not introduce a CNAME coexistence conflict (RFC 1034) or
//     an apex CNAME; the error quotes the offending operation;
//   - after all operations the candidate must still satisfy the
//     whole-zone invariants (validateSet).
func ApplyPatch(cur *Snapshot, ops []PatchOp) ([]dns.RR, error) {
	if len(ops) == 0 {
		return nil, errors.New("patch contains no operations")
	}
	candidate := make([]dns.RR, 0, len(cur.RRs)+len(ops))
	for _, rr := range cur.RRs {
		candidate = append(candidate, dns.Copy(rr))
	}
	for i, op := range ops {
		if op.RR == nil {
			return nil, fmt.Errorf("patch op %d: nil record", i+1)
		}
		if op.RR.Header().Rrtype == dns.TypeSOA {
			return nil, fmt.Errorf("patch op %d: SOA cannot be patched; the serial is assigned at publish time", i+1)
		}
		switch op.Action {
		case "DEL":
			idx := indexOfRecord(candidate, op.RR)
			if idx < 0 {
				return nil, fmt.Errorf("patch op %d: DEL %s: no such record in current version",
					i+1, CanonicalText(op.RR))
			}
			candidate = append(candidate[:idx], candidate[idx+1:]...)
		case "ADD":
			if indexOfRecord(candidate, op.RR) >= 0 {
				return nil, fmt.Errorf("patch op %d: ADD %s: record already exists",
					i+1, CanonicalText(op.RR))
			}
			if err := checkCNAMEConflict(candidate, op.RR, cur.Origin); err != nil {
				return nil, fmt.Errorf("patch op %d: ADD %s: %w",
					i+1, CanonicalText(op.RR), err)
			}
			candidate = append(candidate, dns.Copy(op.RR))
		default:
			return nil, fmt.Errorf("patch op %d: unknown action %q", i+1, op.Action)
		}
	}
	if err := validateSet(candidate, cur.Origin); err != nil {
		return nil, fmt.Errorf("patch rejected, resulting zone invalid: %w", err)
	}
	sortRRs(candidate, cur.Origin)
	return candidate, nil
}

// indexOfRecord finds the exact record — same owner (case-insensitive),
// type, rdata and TTL — or returns -1.
func indexOfRecord(rrs []dns.RR, want dns.RR) int {
	for i, rr := range rrs {
		if sameRecord(rr, want) {
			return i
		}
	}
	return -1
}

func sameRecord(a, b dns.RR) bool {
	ha, hb := a.Header(), b.Header()
	return ha.Rrtype == hb.Rrtype &&
		ha.Ttl == hb.Ttl &&
		strings.EqualFold(ha.Name, hb.Name) &&
		canonicalRdata(a) == canonicalRdata(b)
}

// checkCNAMEConflict enforces the RFC 1034 coexistence rule for a record
// about to be added, checked at ADD time so the error can name the exact
// patch operation that causes the conflict.
func checkCNAMEConflict(candidate []dns.RR, add dns.RR, origin string) error {
	h := add.Header()
	name := strings.ToLower(h.Name)
	if h.Rrtype == dns.TypeCNAME {
		if name == origin {
			return errors.New("CNAME at zone apex is forbidden (apex must keep SOA and NS)")
		}
		for _, other := range candidate {
			if oh := other.Header(); strings.ToLower(oh.Name) == name {
				return fmt.Errorf("CNAME conflicts with existing %s record at %s (RFC 1034)",
					dns.TypeToString[oh.Rrtype], name)
			}
		}
		return nil
	}
	for _, other := range candidate {
		if oh := other.Header(); oh.Rrtype == dns.TypeCNAME && strings.ToLower(oh.Name) == name {
			return fmt.Errorf("%s record conflicts with existing CNAME at %s (RFC 1034)",
				dns.TypeToString[h.Rrtype], name)
		}
	}
	return nil
}
