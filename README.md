# dnszone — local-only authoritative DNS zone service

An authoritative-only DNS server for a single internal test zone
(`lab.test.` by default), backed by PostgreSQL for immutable zone
versions and a change log. It is built for a test lab, not the public
internet:

- **Authoritative only.** Answers come solely from the current zone
  snapshot. There is no recursion, no forwarding, no resolver library
  calls, and the process never opens an outbound connection except to
  its configured PostgreSQL. Out-of-zone names get `REFUSED` with `RA=0`.
- **Explicit record-type allow list.** `SOA, NS, A, AAAA, CNAME, MX,
  TXT, SRV, PTR, CAA` only; any other type in a zone file (e.g.
  `DNSKEY`, `RRSIG`) is rejected at publish time.
- **Atomic publication.** Publishing inserts the full RR set, the change
  log and the current-version pointer in one PostgreSQL transaction
  while holding a row lock on the version counter. The serving layer
  holds an immutable snapshot behind an `atomic.Pointer`; publication is
  one pointer swap, so a query can never observe half a version.
- **Record patches.** Small changes ship as `ADD`/`DEL` record
  operations against the current version instead of a re-edited master
  file. The candidate zone is built in memory, then validated, logged
  and published through the same atomic transaction as a full-file
  publish. A bad operation — deleting a record that does not exist,
  adding one that causes a CNAME conflict — is reported by name, nothing
  is published and the serial does not move.
- **Controlled zone transfers.** AXFR and IXFR are TCP-only, restricted
  to configured source CIDRs **and** require a valid
  [TSIG](https://datatracker.ietf.org/doc/html/rfc8945) signature
  using the HMAC algorithms provided by `miekg/dns`
  (hmac-sha1/224/256/384/512). No home-grown signing.
- **Correct negative answers.** NXDOMAIN and NODATA are authoritative
  (`AA`) and carry the zone SOA in the authority section with TTL
  `min(SOA TTL, SOA MINIMUM)` per RFC 2308.
- **Validation at the edge.** TTLs outside the configured bounds,
  CNAME/other-record coexistence, duplicate CNAMEs, apex CNAMEs, and
  records whose owner is outside the zone are all rejected and the
  publish rolls back.

## Layout

```
cmd/dnszone/         CLI: serve / publish / patch / versions
internal/config/     JSON config (listeners, TTL bounds, ACL, TSIG keys)
internal/zone/       master-file parsing, validation, immutable snapshots,
                     lookup (CNAME chase + wildcards), version diffing,
                     record-patch parsing and application
internal/store/      PostgreSQL: versions, records, change log, LISTEN notify
internal/server/     DNS handler: queries + AXFR/IXFR, TSIG/ACL gating
scripts/             postgres bootstrap and dig verification
testdata/            example zones, an example record patch and a TSIG key file
```

## Requirements

- Go 1.25+
- PostgreSQL 14+ (any reachable instance; tested on 15)
- BIND `dig` for the verification script

## Quick start

1. Prepare the database (example uses a local user-space cluster):

   ```sh
   PG_HOME=$HOME/tools/local ./scripts/start-postgres.sh
   ```

   Any PostgreSQL works; point `database_url` in `config.json` at it.
   The schema is created automatically on first start.

2. Build and publish the first version:

   ```sh
   go build -o bin/dnszone ./cmd/dnszone
   ./bin/dnszone publish -config config.json -file testdata/zone-v1.db --note v1
   ```

3. Serve:

   ```sh
   ./bin/dnszone serve -config config.json
   ```

   The server watches PostgreSQL `LISTEN zone_published` and hot-reloads
   new versions; publish a new file with the same command and queries
   move to the new version atomically.

4. Query and transfer with standard `dig`:

   ```sh
   dig @127.0.0.1 -p 5354 www.lab.test A
   dig @127.0.0.1 -p 5354 -k testdata/tsig.key lab.test. AXFR +tcp
   dig @127.0.0.1 -p 5354 -k testdata/tsig.key lab.test. IXFR=1 +tcp
   ```

## Configuration (`config.json`)

| Key | Meaning |
| --- | --- |
| `zone` | single zone origin to serve (FQDN) |
| `listen_udp` / `listen_tcp` | bind addresses; bind to loopback for a lab-only service |
| `database_url` | PostgreSQL connection string |
| `ttl_min` / `ttl_max` | inclusive TTL window enforced at publish (e.g. 30–86400) |
| `transfer_allow_cidrs` | source networks allowed to AXFR/IXFR (TSIG still required) |
| `tsig_keys` | map of key name (FQDN) → `{algorithm, secret_b64}` |

`secret_b64` is standard base64, the same encoding used in a BIND key
file (`dig -k`).

## Atomicity and transfers

- Each successful publish gets a monotonically increasing serial (the
  SOA serial is rewritten to it) and a stored change log (`ADD`/`DEL`
  rows) derived from the previous version, excluding the SOA itself.
- **AXFR** emits the complete version bracketed by identical SOA RRs.
  Because the handler captures the snapshot pointer once per request, a
  transfer that starts before a publish finishes keeps streaming the
  old version; new transfers get the new one. No mixed stream.
- **IXFR** streams RFC 1995 deltas when the client's serial is a version
  still held in PostgreSQL; an up-to-date client receives a single SOA,
  an ahead-of-server client receives the current SOA, and a missing
  serial falls back to a full AXFR.

## Record patches

When only a few records change, patch the current version instead of
re-editing the master file:

```sh
./bin/dnszone patch -config config.json -file testdata/patch-v1-to-v2.patch --note "v1->v2"
```

A patch file lists one operation per line; each operation names a
complete record including its TTL:

```
# ADD|DEL <owner> <ttl> IN <type> <rdata>
ADD host2 3600 IN A 127.0.0.30
DEL www 3600 IN TXT "multi-record same name v1"
ADD www 3600 IN TXT "multi-record same name v2"
```

- Owners may be relative to the zone origin (`www`, `@`) or absolute;
  blank lines and `#`/`;` comments are ignored. The TTL is mandatory on
  every record, and the SOA cannot be patched (its serial is assigned at
  publish time).
- Operations apply in order to an in-memory candidate built from the
  current version. `DEL` must name a record that exists (owner, type,
  rdata **and** TTL all match); `ADD` must not duplicate an existing
  record and must not create a CNAME coexistence conflict (RFC 1034) or
  an apex CNAME. A TTL change is a `DEL` plus an `ADD`.
- The candidate then goes through the same zone validation, change-log
  generation and single-transaction publish as a full-file publish, so
  queries and AXFR/IXFR move to the new version together.
- Any failing operation is reported by content (e.g. `patch op 1: DEL
  nosuch.lab.test. 3600 IN A 127.0.0.99: no such record in current
  version`), the whole patch is rejected, no partial result is
  published and the serial does not move.

## Tests

```sh
go test -race ./...
```

- `internal/zone`: TTL boundaries, same-name multi-records, CNAME
  conflicts, out-of-zone/unsupported-type rejection, CNAME chains,
  wildcards, negative TTL, diff and AXFR ordering, record-patch parsing
  and application (missing-record deletes, CNAME conflicts, duplicate
  adds, TTL changes).
- `internal/server`: AA/no-recursion answers, NXDOMAIN/NODATA
  authority, out-of-zone REFUSED, atomic snapshot swap, TSIG+ACL
  transfer gating over real DNS sockets, and an end-to-end patch
  release where queries and AXFR observe the same new version.
- `internal/store` (runs against PostgreSQL; creates/uses
  `dnszone_test`): publish/load, rollback of invalid publishes,
  concurrent publishing with no serial gaps, change-log contents, and
  record patches (mixed A+TXT patch, failed patches leaving the serial
  untouched, full-file publish after a patch).

An end-to-end `dig` checklist (flags, negatives, AXFR/IXFR content and
TSIG bookends) lives at `scripts/verify-dig.sh`.

## Security notes

- Malformed/truncated/random packets were fuzzed (thousands of probes):
  the server keeps serving and every reply is a well-formed response.
- Hostile inputs (out-of-zone names, external CNAME targets) do not
  cause any outbound connection: the only established outbound sockets
  are the pool connections to PostgreSQL. There is no HTTP client, no
  dialer, no `net.Resolver` use.
- DNS UPDATE (opcode 5) is answered NOTIMP; only standard queries are
  processed.
- TSIG secrets are configuration data; protect `config.json` like a
  BIND key file.
