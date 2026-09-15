# Evidence format (byte-exact profile for third-party verifiers)

Everything a verifier needs to re-check this project's evidence without running its code. Reference
implementation: `health_verify.py`; independent re-implementations: `verifiers/js`, `verifiers/go`,
`verifiers/rust`; `verifiers/differential.py` keeps the four in agreement on intact and tampered fixtures.

## Canonical JSON — two profiles

Both: keys sorted by Unicode code point, separators `,` and `:` with no spaces, `NaN`/`Infinity` forbidden,
duplicate keys forbidden, nesting ≤ 512.

| profile | where | non-ASCII | control chars |
|---|---|---|---|
| **ASCII** (Python `ensure_ascii=True`) | signed audit records (`audit_locale_ledger.jsonl`) | `\uXXXX`, lowercase hex, surrogate pairs above U+FFFF | `\n \r \t \b \f`, else `\u00XX` |
| **UTF-8** (Python `ensure_ascii=False`) | `self_hash` ledgers (`prealert_ledger.jsonl`, `fascicoli_ledger.jsonl`), the verbale | raw UTF-8, never escaped (U+2028/2029, `<>&` included) | same |

**Numbers — integers included — are re-emitted exactly as written in the file** (`-0` stays `-0`). The file was written by Python from the same
objects that were hashed, so the number text in the file *is* the canonical text (Python's shortest
`repr`: `12.0`, `1e-05`, `1e+16`). A verifier must therefore keep the lexeme of every number instead of
parsing it to a double and printing it again — that is what the four verifiers do. Since v0.5.0 signed
audit records carry **no floats at all** (`latenza_dichiarata_ms`, `eta_arrivo_min`,
`tempo_porta_intervento_min` are integers); older records may contain floats and still verify.

Timestamps are opaque strings (`2026-09-15T18:58:21+00:00`, sometimes with microseconds): never re-parsed
or re-formatted before hashing.

## Signed audit record (`kind: audit_locale`)

Signed key set, exactly: `kind, target, azione, dettaglio, operatore, ts, prev_sha256` and, since
v0.5.0, `alg` (`"ed25519"`). Lines written before 13/09/2026 have no `prev_sha256`; lines before v0.5.0 have
no `alg`. Unsigned companions: `record_sha256`, `firma_ed25519_b64`, `pubkey_b64`. **Any other key is a
failure** (a line enriched after the fact is not the signed line).

```
record_sha256 = SHA-256( canonical_ASCII( {signed keys} ) )          # hex
signature     = Ed25519( sk_operator, raw 32-byte digest )            # base64, 64 bytes
```

The signature is over the **raw digest bytes**, not over the hex string and not over the record. It is
verified against the **registered** key of the operator (`.audit_keys/fb-<slug>.pub`, base64 raw 32 bytes,
`slug` = lowercase, non-alphanumerics → `-`, max 40 chars), never against `pubkey_b64` in the line. With no
registry (or no Ed25519 implementation) the verdict is *NOT-TRUSTED*, never PASS and never FAIL: FAIL is reserved
for verified falsity (a digest that does not match, a registered key that does not sign, a line whose key set is
not the signed one — mandatory keys missing or extra keys present). The registry embedded in a verbale
(`registro_chiavi`) may be accepted only on explicit request and is declared as not out-of-band. Operators from
installations older than 13/09/2026 that have a `.key` but no `.pub` are enrolled only by an explicit command
(`python3 audit_bridge.py --enrol-legacy`), never during verification.

Chain: `prev_sha256` of the first chained line is the literal string `GENESIS`; afterwards it is the
`record_sha256` of the previous line. `GENESIS` after the chain started, a line without `prev_sha256` after
the chain started, or a mismatch, is a break. Every line's digest is recomputed, not only the lines of one
pre-alert. Limit (declared): truncating the tail and appending fresh lines stays consistent — the
timestamped, persisted verbale is what covers that.

## `self_hash` ledgers (pre-alert anchors, mission case files)

```
self_hash = SHA-256( canonical_UTF8( line minus self_hash ) )        # hex
prev_hash = self_hash of the previous line; genesis = 64 zeros
```

Written under an exclusive file lock (`<ledger>.lock`, `fcntl.flock`) since v0.5.0 for every ledger.

## Verbale (`kind: verbale_probatorio_prealert`)

```
digest_verbale_sha256 = SHA-256( canonical_UTF8( verbale minus digest_verbale_sha256 ) )
```

The persisted file is pretty-printed (`indent=1`); the verifier re-canonicalises it (numbers kept as text).
Each event of the verbale carries the `record_sha256` of its audit line: a third party checks that every
event exists in the audit ledger and verifies there. `latenza_emissione_ricezione_ms` is **measured** from
the crew-signed emission line to the ED-signed receipt line; `latenze_dichiarate_dal_ricevente` are what the
receiver declared and are not a measurement.

## Commitments of low-entropy values

Coordinates, hospital names, board messages and notes are enumerable: since v0.5.0 the **board** ledger records
carry `HMAC-SHA256(sale, utf8)` with a random 16-byte `sale` that lives only in the board's memory (`impegno()`);
positions are committed as integer micro-degrees `lat_e6,lon_e6` rounded **half away from zero**
(`floor(|x|·1e6 + 0.5)` with the sign restored — Python's `round` is half-to-even, JS `Math.round` half-up: the
rule is fixed here). Whoever holds value and sale can prove; whoever holds the disk reads nothing; after the
board record expires nobody can open the commitment (by design). The **mission case file** has no in-memory
board to keep a salt: its `motivo`/`nota` are **unsalted** `sha256` fingerprints (declared, enumerable for
low-entropy texts). Older records carry bare `sha256` fingerprints everywhere.

## Crypto-agility

`alg` is part of the signed record. The only value today is `ed25519`; a verifier refuses any other. A
post-quantum scheme (e.g. ML-DSA-65) would be a new value, not a new format. NIST IR 8547 (draft) proposes
disallowing Ed25519 after 2035 — inside the retention windows of clinical records.
