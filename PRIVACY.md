# Privacy Policy — OMEGA Health Companion

_Last updated: 2026-09-11_

## What this software is

OMEGA Health Companion is **self-hosted software**, not a service: the author operates
no servers, collects no data, and receives no telemetry. Every deployment is operated
by the organisation that installs it (typically an emergency medical service or
hospital), which acts as the **data controller** under applicable law. This document
describes how the software itself handles data, so that a deploying controller can
meet its own obligations.

## Privacy by design (how data flows)

- **Vital signs, medications and clinical flags are processed in memory only**, for
  the immediate care flow (ambulance → destination hospital pre-alert). They are not
  written to disk by default and vanish with the process.
- **The provenance ledger stores SHA-256 digests only — never health data.** It proves
  *that* a pre-alert existed at a time, unaltered, without containing it (see
  `scores_emergenza.ancora_prealert`, default `payload="digest"`).
- **The FHIR export is anonymised**: age only; no name, no identifiers, no birth date.
  Identity linkage happens inside the hospital's own systems, in the care flow.
- **Confirmation signatures** bind operator name, time and meaning to a record digest —
  professional accountability data (staff, not patients), retained in the audit trail.
- **Authentication tokens and signing keys** are generated locally, stored with 0600
  permissions, and never leave the machine.
- **No third-party services**: no analytics, no cloud, no external calls in the care
  flow. The board web app binds to localhost by default.

## What is at rest, precisely (2026-09-11)

- `prealert_ledger.jsonl`: digests only (`prealert_sha256`, chain hashes, timestamps). No vital sign,
  no age, no free text.
- Audit trail (`audit_locale_ledger.jsonl`, or the Part 11 trail when the optional engine is present):
  operator, action, timestamps, record digests, and — for confirmation notes — the note's SHA-256 and
  length only. Until 2026-09-11 the note text itself was written to disk; it no longer is.
  **Exception, by design:** the *administrative reason* an operator types when removing a note
  (`/rimuovi-nota`) is stored in clear — it is the justification 21 CFR Part 11 requires for a
  deletion, and it must not contain patient data (the removed note itself is bound by digest).
- The ED board is in memory only; a record's clinical payload is dropped after `OMEGA_BOARD_TTL_H`
  hours (default 24), on every read.
- Operator signing keys (`.audit_keys/`, mode 0600) are local secrets, not health data.

## Legal bases and applicable law (for EU deployments)

For a deploying healthcare controller in the EU, processing of health data in the care
flow rests on **GDPR art. 6(1) and art. 9(2)(h)** (provision of health care), performed
by or under the responsibility of professionals subject to secrecy. The software
supports **data minimisation (art. 5(1)(c))** and **data protection by design and by
default (art. 25)** as described above: nothing more than the care flow needs is
processed, and nothing identifying is persisted by the software itself. Subject-rights
requests (arts. 15–22) are addressed to the deploying controller; the software holds no
personal data at rest to disclose or erase, apart from the operator-accountability
audit trail, which the controller manages under its staff-data policies.

## What this software is NOT

- It is **not a medical device** (no MDR certification) and must not be used for real
  clinical decisions outside a supervised, approved pilot.
- It performs **no surveillance, no profiling, no biometrics**, and computes nothing
  about individuals beyond the standard clinical scores its documentation declares.
- Adult patients only: for age < 16 the software refuses to score (fail-closed).

## Contact

Questions about this software's data handling: open an issue on the repository.
Questions about a specific deployment's data handling: contact the deploying
organisation (the data controller).
