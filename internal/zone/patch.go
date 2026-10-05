package zone

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// Operation is one explicit record-patch action. RR is the complete
// resource record, including its TTL: DEL matches owner, type, class,
// rdata and TTL exactly, while ADD inserts that same record.
type Operation struct {
	Line   int    // 1-based line in the patch file
	Action string // "ADD" or "DEL"
	RR     dns.RR
}

// ParsePatch reads a line-oriented record patch. Each non-comment line is
// either "ADD <complete RR>" or "DEL <complete RR>". Record syntax is the
// same RFC 1035 master-file syntax used by full zone files; every record
// must carry an explicit TTL, because patches cannot inherit a file-wide
// $TTL. The patch does not modify the SOA: its serial is allocated by the
// publisher.
func ParsePatch(r io.Reader, origin string) ([]Operation, error) {
	origin = dns.Fqdn(origin)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var ops []Operation
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "$") {
			return nil, fmt.Errorf("patch line %d: zone-file directives are not supported in a record patch", lineNo)
		}

		action, body, ok := strings.Cut(line, " ")
		if !ok {
			if action, body, ok = strings.Cut(line, "\t"); !ok {
				return nil, fmt.Errorf("patch line %d: expected ADD or DEL followed by a complete resource record", lineNo)
			}
		}
		action = strings.ToUpper(strings.TrimSpace(action))
		body = strings.TrimSpace(body)
		if body == "" {
			return nil, fmt.Errorf("patch line %d: expected ADD or DEL followed by a complete resource record", lineNo)
		}
		if action != "ADD" && action != "DEL" {
			return nil, fmt.Errorf("patch line %d: action %q must be ADD or DEL", lineNo, action)
		}
		if err := requireExplicitTTL(lineNo, action, body); err != nil {
			return nil, err
		}

		zp := dns.NewZoneParser(strings.NewReader(body+"\n"), origin, "patch")
		rr, more := zp.Next()
		if !more {
			if err := zp.Err(); err != nil {
				return nil, fmt.Errorf("patch line %d: %s %s: %w", lineNo, action, body, err)
			}
			return nil, fmt.Errorf("patch line %d: %s: expected one complete resource record", lineNo, action)
		}
		if rr2, stillMore := zp.Next(); stillMore {
			return nil, fmt.Errorf("patch line %d: each ADD/DEL line must contain exactly one resource record (%s and %s)",
				lineNo, CanonicalText(rr), CanonicalText(rr2))
		}
		if err := zp.Err(); err != nil {
			return nil, fmt.Errorf("patch line %d: %s %s: %w", lineNo, action, body, err)
		}
		if err := validateRR(rr, origin, Limits{MinTTL: 0, MaxTTL: ^uint32(0)}); err != nil {
			return nil, fmt.Errorf("patch line %d: %s %s: %w", lineNo, action, body, err)
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			return nil, fmt.Errorf("patch line %d: %s %s: SOA cannot be patched; the publisher allocates its serial",
				lineNo, action, CanonicalText(rr))
		}
		ops = append(ops, Operation{Line: lineNo, Action: action, RR: dns.Copy(rr)})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read patch: %w", err)
	}
	if len(ops) == 0 {
		return nil, errors.New("patch contains no record operations")
	}
	return ops, nil
}

func requireExplicitTTL(lineNo int, action, body string) error {
	tokens := tokenizeMasterLine(body)
	if len(tokens) < 3 {
		return fmt.Errorf("patch line %d: %s: record must contain owner, explicit TTL, type and rdata", lineNo, action)
	}
	i := 1
	if i < len(tokens) && strings.EqualFold(tokens[i], "IN") {
		i++
	}
	if i >= len(tokens) {
		return fmt.Errorf("patch line %d: %s: missing explicit TTL", lineNo, action)
	}
	if _, err := strconv.ParseUint(tokens[i], 10, 32); err != nil {
		return fmt.Errorf("patch line %d: %s: explicit numeric TTL is required (got %q)", lineNo, action, tokens[i])
	}
	return nil
}

// tokenizeMasterLine splits one master-file RR line while preserving
// quoted strings. A semicolon outside quotes starts a comment.
func tokenizeMasterLine(line string) []string {
	var tokens []string
	var b strings.Builder
	inQuote, escaped, inToken := false, false, false
	flush := func() {
		if inToken {
			tokens = append(tokens, b.String())
			b.Reset()
			inToken = false
		}
	}
	for _, r := range line {
		if inQuote {
			b.WriteRune(r)
			inToken = true
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' {
				inQuote = false
			}
			continue
		}
		switch {
		case r == ';':
			flush()
			return tokens
		case r == '"':
			inQuote = true
			inToken = true
			b.WriteRune(r)
		case unicode.IsSpace(r):
			flush()
		default:
			inToken = true
			b.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// OperationError identifies the patch operation responsible for a failure.
// A failed patch returns all detected operation errors and publishes
// nothing.
type OperationError struct {
	Line   int
	Op     Operation
	Reason string
}

func (e *OperationError) Error() string {
	line := e.Line
	if line == 0 {
		line = e.Op.Line
	}
	return fmt.Sprintf("patch line %d: %s %s: %s", line, e.Op.Action, CanonicalText(e.Op.RR), e.Reason)
}

// ApplyPatch builds a candidate snapshot from base and ops. It validates
// TTL bounds and all whole-zone invariants before returning, so callers
// only publish the candidate after every ADD and DEL has succeeded.
func ApplyPatch(base *Snapshot, ops []Operation, lim Limits) (*Snapshot, error) {
	if base == nil {
		return nil, errors.New("cannot apply record patch: no current zone version; publish a full master file first")
	}
	if len(ops) == 0 {
		return nil, errors.New("patch contains no record operations")
	}

	currentExact := map[string][]dns.RR{}
	currentIdentity := map[string]int{}
	for _, rr := range base.RRs {
		k := diffKey(rr)
		currentExact[k] = append(currentExact[k], dns.Copy(rr))
		currentIdentity[rrKey(rr)]++
	}

	var (
		errs      []error
		effective []Operation
	)
	for i, op := range ops {
		if op.Action != "ADD" && op.Action != "DEL" {
			errs = append(errs, opError(i, op, "action must be ADD or DEL"))
			continue
		}
		if err := validateRR(op.RR, base.Origin, lim); err != nil {
			errs = append(errs, opError(i, op, err.Error()))
			continue
		}
		if op.RR.Header().Rrtype == dns.TypeSOA {
			errs = append(errs, opError(i, op, "SOA cannot be patched; the publisher allocates its serial"))
			continue
		}

		ek := diffKey(op.RR)
		ik := rrKey(op.RR)
		switch op.Action {
		case "DEL":
			if len(currentExact[ek]) == 0 {
				reason := "record does not exist in the current version"
				if same := currentIdentityRecords(currentExact, ik); len(same) > 0 {
					reason = "record does not exist with that exact TTL and rdata; current match(es): " +
						strings.Join(canonicalTexts(same), "; ")
				}
				errs = append(errs, opError(i, op, reason))
				continue
			}
			currentExact[ek] = currentExact[ek][1:]
			if currentIdentity[ik] > 0 {
				currentIdentity[ik]--
			}
			effective = append(effective, op)
		case "ADD":
			if len(currentExact[ek]) > 0 {
				errs = append(errs, opError(i, op, "record already exists in the current version; use DEL first to change it"))
				continue
			}
			if currentIdentity[ik] > 0 {
				reason := "the same owner/type/rdata already exists with a different TTL; DEL the old record first"
				if matches := currentIdentityRecords(currentExact, ik); len(matches) > 0 {
					reason += ": " + strings.Join(canonicalTexts(matches), "; ")
				}
				errs = append(errs, opError(i, op, reason))
				continue
			}
			currentExact[ek] = append(currentExact[ek], dns.Copy(op.RR))
			currentIdentity[ik]++
			effective = append(effective, op)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	var candidate []dns.RR
	for _, rrs := range currentExact {
		for _, rr := range rrs {
			candidate = append(candidate, rr)
		}
	}

	if err := validateSet(candidate, base.Origin); err != nil {
		return nil, errors.Join(patchOperationDiagnostics(err, candidate, effective)...)
	}
	snap, err := NewSnapshot(base.Origin, base.Serial, candidate)
	if err != nil {
		return nil, err
	}
	if len(Diff(base, snap)) == 0 {
		return nil, errors.New("patch makes no record changes")
	}
	return snap, nil
}

func opError(index int, op Operation, reason string) error {
	line := op.Line
	if line == 0 {
		line = index + 1
	}
	return &OperationError{Line: line, Op: op, Reason: reason}
}

func currentIdentityRecords(current map[string][]dns.RR, identity string) []dns.RR {
	var out []dns.RR
	for _, rrs := range current {
		for _, rr := range rrs {
			if rrKey(rr) == identity {
				out = append(out, rr)
			}
		}
	}
	return out
}

func canonicalTexts(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, CanonicalText(rr))
	}
	return out
}

// patchOperationDiagnostics turns a final candidate-set validation failure
// into errors naming the specific ADD/DEL operation(s) responsible.
func patchOperationDiagnostics(validateErr error, candidate []dns.RR, ops []Operation) []error {
	var diags []error
	candidateByName := map[string][]dns.RR{}
	for _, rr := range candidate {
		name := strings.ToLower(rr.Header().Name)
		candidateByName[name] = append(candidateByName[name], rr)
	}

	for i, op := range ops {
		h := op.RR.Header()
		name := strings.ToLower(h.Name)
		atName := candidateByName[name]
		types := map[uint16]int{}
		var cnameCount int
		for _, rr := range atName {
			types[rr.Header().Rrtype]++
			if rr.Header().Rrtype == dns.TypeCNAME {
				cnameCount++
			}
		}

		switch {
		case op.Action == "ADD" && h.Rrtype == dns.TypeCNAME && (name == candidateApex(candidate) || cnameCount > 1 || len(types) > 1):
			diags = append(diags, opError(i, op, "ADD creates an illegal CNAME in the candidate zone: "+describeCandidateRecords(atName)))
		case op.Action == "ADD" && h.Rrtype != dns.TypeCNAME && cnameCount > 0:
			diags = append(diags, opError(i, op, "ADD conflicts with a CNAME at the same owner in the candidate zone: "+describeCandidateRecords(atName)))
		case op.Action == "DEL" && h.Rrtype == dns.TypeNS && types[dns.TypeNS] == 0:
			diags = append(diags, opError(i, op, "DEL removes the last apex NS record"))
		}
	}
	if len(diags) == 0 {
		return []error{fmt.Errorf("candidate zone validation failed: %w", validateErr)}
	}
	return diags
}

func candidateApex(rrs []dns.RR) string {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			return strings.ToLower(rr.Header().Name)
		}
	}
	return ""
}

func describeCandidateRecords(rrs []dns.RR) string {
	parts := canonicalTexts(rrs)
	if len(parts) == 0 {
		return "no records"
	}
	return strings.Join(parts, "; ")
}
