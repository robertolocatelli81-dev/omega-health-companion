# OMEGA Health Companion — open pre-hospital alerting with tamper-evident evidence

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539173.svg)](https://doi.org/10.5281/zenodo.22539173)

**Ambulance → hospital pre-alert engine, open and self-hosted.** During transport it
computes **validated clinical scores** (NEWS2 · RCP 2017, BE-FAST, qSOFA · Sepsis-3,
CDC/ATLS trauma criteria, ERC arrest logic, ESC STEMI pathway), screens for known
severe drug interactions, and produces **one integrated pre-alert** so the emergency
department prepares the right team *before* arrival. Every pre-alert is anchored to an
append-only **SHA-256 hash-chain (digest only — no health data on disk)** and every
issue/confirmation can carry a **record-bound electronic signature** (who issued, who
took charge, when).

**License:** AGPL-3.0-or-later · **Language:** Python 3, stdlib + `cryptography` (declared dependency since
0.6.1: every event that goes through the audit bridge — pre-alert issue, confirmation, reception, coordination and incident events — is signed, by the Part 11 engine when present or by the built-in Ed25519 signer that needs `cryptography`, and the bridge refuses to record them unsigned unless you opt in
with `OMEGA_HEALTH_ALLOW_UNSIGNED=1`) · **Author:** Roberto Locatelli, 2026

## Honest scope (read this first)

- **Not a medical device.** Not certified, not clinically validated. It computes
  *recognised standard scores* (arithmetic from published tables, plus ONE declared
  modification of the escalation bands, below — no AI diagnosis) and communicates them. **The physician decides.**
  One **declared deviation** from the RCP NEWS2 escalation bands: a single parameter scoring 3
  is escalated to MEDIUM here (RCP: low-medium), stated in every output as
  `deviazione_dichiarata`; the 587-vector certificate covers the arithmetic, not the bands.
- Real clinical use requires a supervised pilot and the applicable regulatory path
  (EU MDR). This codebase is the *engine* for such a pilot.
- Adult patients only: for age < 16 the system **refuses to score** (fail-closed;
  adult scores are not validated in children) instead of producing a wrong number — enforced in the
  API and, since v0.5.0, in `barella_prealert.prealert()` itself.
- **Regulatory exposure, stated:** a server that computes a priority and the team to alert for a
  patient may fall under EU MDR Rule 11 (class IIa) once placed on the market with a medical purpose;
  nothing here is CE-marked and no IEC 62304 life-cycle file exists yet. Until a pilot with a sponsor
  produces that file, the intended use is *evidence of the pre-alert as communicated*, not decision support.
- **What the signatures prove, stated:** operator keys are generated on the server on first use
  (trust-on-first-use) and registered there; a receipt therefore proves *that the server's ledger was not
  altered after the fact* and *which registered key signed*, not the legal identity of the person behind
  the key. Non-repudiation opposable to third parties needs hospital SSO / eID-bound keys or a QTSP
  (roadmap), and the seal of the persisted verbale is what covers a truncated ledger tail.
- **Verifiable by third parties without this code:** `health_verify.py` and its independent
  re-implementations in JavaScript, Go and Rust (`verifiers/`) re-check the signed audit ledger, the
  hash-chained ledgers and a verbale; the byte-exact profile is in `FORMAT.md`. Signed records carry an
  `alg` field so a post-quantum scheme can be introduced without changing the format.
- Implausible vitals (broken sensor, °F/fraction unit confusion) are **rejected with
  the offending fields named** — never turned into a plausible-looking score. Since 2026-09-11 this
  is also **type-strict**: a clinical flag must be a JSON boolean (a string `"no"` used to be read as
  *true* — i.e. as "alert" — and a JSON `true` in a numeric field used to score as the number 1), and
  age is required (no age → no adult score, the paediatric gate cannot decide). See CHANGELOG.
- The drug-interaction registry is a **declared non-exhaustive seed**: absence of an
  alert never means "safe".

## What's inside

| Module | What it does |
|---|---|
| `barella_prealert.py` | NEWS2 (official RCP 2017 tables, SpO2 scale 1 **and** scale 2 for hypercapnic patients) + fail-closed vitals validation |
| `scores_emergenza.py` | BE-FAST (posterior circulation included), qSOFA, CDC/ATLS trauma activation, ERC-conformant arrest logic (pulse check treated as unreliable), STEMI pathway; digest-only ledger anchor |
| `interazioni_farmaci.py` | Known severe drug interactions (multi-class aware, e.g. tramadol as opioid *and* serotonergic) |
| `ambulanza_intelligente.py` | The integrated pre-alert: priority elevation on any time-critical pathway, route-level warnings (⛔ no nitrates with PDE5 inhibitors; ⚠️ anticoagulated trauma → trauma centre), paediatric gate |
| `team_comms.py` | Real self-hosted team app: server-side scoring (`POST /valuta`), token auth, ED board, confirmations, `GET /fhir/<id>`, `GET /atmist/<id>`, `GET /audit` |
| `fhir_chems.py` · `chems_ingest.py` | Pre-alert → **CH EMS document** (Swiss mission protocol, 0 validator errors on two documents, see below); reader + scoring + evidence for CH EMS documents from any ePCR |
| `fhir_export.py` | Pre-alert → **FHIR R4 Bundle** (LOINC-coded vitals conformant to the R4 vital-signs profiles — BP as the 85354-9 panel with diastolic `dataAbsentReason` when not measured, SpO2 as 2708-6 + 59408-5; 0 structural errors on both HAPI `$validate` and the HL7 `validator.fhir.org`, re-checked 2026-09-11 — RiskAssessment, Provenance carrying the ledger hash) — validated with **0 errors** against the public HAPI FHIR validator; ATMIST handover; ECG attachment by SHA-256 (never auto-interpreted) |
| `ambulanza_cli.py` | Field CLI: raw vitals in, computed pre-alert back; honest fallback message if the server is unreachable |
| `audit_bridge.py` | Bridge to a 21 CFR Part 11-grade audit engine (signed audit trail, signatures bound to records with meaning; the engine is not part of this repository), with a built-in local Ed25519 signer (`cryptography`) when the engine is absent. **Fail-closed since 0.6.1:** with neither, it raises `FirmaNonDisponibile` and `team_comms` refuses to start; recording events at the declared unsigned "base" level is possible only behind the explicit opt-in `OMEGA_HEALTH_ALLOW_UNSIGNED=1` (a declared limitation of that mode: with no trail, pre-alert ids restart from 1 after a restart, so they are not stable identifiers) (`verifica_trail()` stays a read-only diagnostic and simply reports that the engine is absent) |
| `companion_seed.py` | Citizen-facing claim verification seed (informative only) |
| `mission_case.py` | **Mission case file**: declarative FSM (ALLERTA→VALUTAZIONE→TRASPORTO→CONSEGNATA→CHIUSA, +ANNULLATA), SHA-256 hash-chained append-only ledger under an exclusive file lock, digests-only (no PHI), monotonic-clock guard, tamper → pack refused. Optional private case-engine adds an independent double replay; degrades honestly to "fascicolo-locale" (verified: same 17 tests pass with and without the engine) |
| `prealert_criteria.py` | **RCEM/AACE 2025 pre-alert criteria** (adult thresholds adapted from NEWS2, paediatric table by age band adapted from PEWS, 16 specific conditions, JRCALC high-risk sepsis markers) transcribed from the July 2025 UK national guideline (PDF SHA-256 pinned) — says *whether* the guideline indicates a pre-alert and *why*; "headline + ETA first, then ATMIST, ≤60 s" message. Declared scope: no BP trend, no "new for patient" GCS; children get *criteria*, never an adult score |
| `verbale_probatorio.py` | **Evidentiary record of the pre-alert** ("recorded line" made verifiable): signed ED *receipt* (who answered, role, response requested vs enacted, reason-by-digest if different, latency), per-pre-alert *verbale* that re-verifies every signature against the operator's registered key and the signed hash chain, detects tampering, re-signing and deletions, optional **RFC 3161 timestamp** on the verbale digest with CMS-signature verification and persisted bytes — level declared (`rfc3161-non-qualificata`: a QTSP on the EU Trusted List is needed for an eIDAS *qualified* timestamp) |
| `coordinamento.py` | **What the field leaders do, done the OMEGA way** (compared online 2026-09-13 with Pulsara, Twiage, corpuls.mission, NIDA): patient type → team to alert (from the computed pathways and the 2025 conditions, closed vocabulary), en-route ETA/position updates, two-way crew↔ED messages, ECG/scene-photo/document attachments (magic-byte checked), "close the loop" clinical outcome, QA/QI metrics (latency, alternative responses, over/under-triage proxies), major incidents with several patients. Every event is signed; free text and bytes live only in memory with the board TTL; the ledger holds digests and closed values |
| `test_input_types.py` | **31 tests** (23 distinct methods, 4 API cases re-run in three server contexts) — the hostile-input red-team cases of 2026-09-11 in three rounds (string flags in vitals, `clinica` and FAST signs, boolean vitals, missing/invalid age, malformed drug list, client-computed pre-alert, note persistence, board retention); 14 of them red on the code they were written against, the rest positive controls; unit + end-to-end over HTTP |
| `test_health.py` | **21 tests**: unit benches (positive + null controls, incl. a bench-of-the-bench that must fail) + end-to-end over real HTTP (auth rejected, °F detected, ledger chain verified, CLI against live server) |

## Quick start

```bash
python3 test_health.py                  # 23 tests (unit benches + E2E over localhost)
python3 test_mission_case.py            # 17 tests — mission case file (both engine levels)
python3 test_input_types.py             # 31 tests — hostile input types (red-team 2026-09-11, three rounds)
python3 test_news2_certificate.py       #  4 tests — NEWS2 certificate
python3 test_prealert_2025.py           # 49 tests — RCEM/AACE 2025 criteria at the boundaries, ED receipt, verbale, tamper/re-sign/deletion detection
python3 test_coordinamento.py           #  4 tests — patient types, incidents, ETA/position, messages, attachments, outcomes, metrics, expiry (end-to-end)
# 128 tests in these six files; CI runs ALL fifteen test_*.py files (200 tests, run green 2026-09-18 in six configurations: with and without `cryptography`, `OMEGA_PROFILO` absent / exported as `comunicazione` / exported as `punteggi`, each file alone and all collected in one process) on every push, never with the private engine
# HEALTH_TSA_URL=https://freetsa.org/tsr HEALTH_TSA_CAFILE=cacert.pem python3 test_prealert_2025.py   # + 2 opt-in network tests: real RFC 3161 timestamp, trust chain, wrong CA refused
python3 team_comms.py 8097              # ED board on http://127.0.0.1:8097/
python3 ambulanza_cli.py --rr 28 --spo2 89 --o2 --sbp 85 --hr 135 --non-alert \
        --temp 39.4 --eta 67 --arrivo 8 --farmaci warfarin aspirina
```

A systemd user unit is provided in `deploy/` (loopback by default; put TLS in front
before exposing beyond localhost).

## Evidence of the pre-alert: signed, hash-chained, verifiable offline (2026-09-13)

The UK national pre-alert guideline (RCEM / AACE, July 2025) asks that pre-alert calls be made on a
*recorded line*, be received by a senior clinician who can enact the response, and that an
*alternative* response is discussed openly and is not a failure. This companion turns those three
sentences into evidence a third party can verify: `POST /ricezione` records the ED receipt (operator,
role, response requested vs enacted, reason by digest, emission→receipt latency) with the same signature
discipline as confirmations; `GET /verbale/<id>` returns the digest-only evidentiary record of a pre-alert
with every signature re-verified from the canonical record **against the operator's registered key**
and the signed `prev_sha256` chain checked over the whole ledger, and `?marca=1` adds an RFC 3161
timestamp on its digest when `HEALTH_TSA_URL` is set (token CMS signature verified with the embedded
certificate; `verified` is True **only** when the chain to the CA in `HEALTH_TSA_CAFILE` also holds,
None without a CA, False with a wrong one; the stamped bytes are persisted under `verbali/`;
level declared — not an eIDAS *qualified* timestamp unless the TSA is a QTSP). Every field is
closed-vocabulary or a digest: no free text and no health data in the ledgers (the optional board journal of 0.7.0 is encrypted at rest, see PRIVACY.md and INTENDED_USE.md).

## Compared with the field (read online on 2026-09-13, re-read from primary sources on 2026-09-18)

The competitor column is what the vendors *state* (quotes and page digests in the release notes of 0.7.2); the OMEGA column is
*measured* on the running 0.7.2 server in both profiles. Rows marked **(punteggi)** exist only with `OMEGA_PROFILO=punteggi`;
a standard installation (default `comunicazione`) returns them as not computed.

| Capability | Pulsara / TigerConnect (ex Twiage) / corpuls / NIDA | OMEGA Health Companion |
|---|---|---|
| Pre-arrival notification with vitals, ETA | yes | yes (`/valuta`); the **national 2025 criteria** saying *why* **(punteggi)** |
| Patient types → team | Pulsara: 12 patient types (incl. General) | `tipo_paziente` / `team_da_allertare`, derived, closed vocabulary **(punteggi)** |
| ECG / photo / document sharing | yes | `POST /allegato/<id>` — bytes in memory (TTL), digest in the signed ledger, magic bytes checked |
| GPS / ETA updates en route | yes | `POST /posizione` — exact position in memory, only ETA + a **salted commitment** (HMAC-SHA256, salt in memory) of the position in the ledger: a bare digest of coordinates was enumerable |
| Two-way secure chat | yes | `POST /messaggio` — text in memory, salted commitment signed; provable only while the board record (and its salt) lives |
| Outcome feedback ("close the loop") | Pulsara | `POST /esito` — closed vocabulary, signed |
| QA/QI performance data | Pulsara (NEMSIS-formatted database integration), corpuls ANALYSE | `GET /metriche` — aggregates, no identifiers; over/under-triage proxies **(punteggi)**, `null` otherwise |
| Mass-casualty / multi-patient | Pulsara | `POST /incidente`, `GET /incidente/<id>`, START tags per patient (`POST /triage`, signed, re-triage allowed) |
| ED status / divert | Pulsara (ED Availability); TigerConnect: not stated | `POST /stato_ps` — accetta / saturo / dirotta, signed, returned with every pre-alert |
| Escalation when nobody takes the call | not documented as a product feature by any vendor; a regional EMS advisory using Pulsara tells crews to phone after 60 s without acknowledgement | `da_escalare` in `GET /metriche` (no receipt after 120 s) |
| **Evidentiary record of the pre-alert** (who said what, who answered, chain, timestamp) | corpuls: delegations «dreifach rechtssicher dokumentiert» (device data, LIVE mission report, paper print) and audit logging of privacy-relevant accesses; Pulsara: «time-stamped source of truth for each case»; none documents a record **verifiable by a third party offline** (registered keys, hash chain, independent verifiers) | `GET /verbale/<id>` + four offline verifiers (Python, JS, Go, Rust); a tampered ledger fails in all — this is the difference |
| Audio/video calls, live 12-lead telemetry | yes | **not done**: infrastructure, not evidence; integrate with those tools instead |
| Patient identity lookup / pre-registration | TigerConnect («registered before arrival») | **not done by design**: PII-free |
| NEMSIS export | US products | **not done**: FHIR R4 is the European road |
| MDR certification | corpuls.mission LIVE («zertifiziert als Medizinprodukt nach Verordnung (EU) 745/2017», class not stated) | **not yet**: the default profile is outside the qualification in our reading of the Swissmedic Merkblatt (INTENDED_USE.md); `punteggi` declares the Rule 11 exposure; pilot + class IIa file are the roadmap |

## CH EMS (Switzerland) — measured, not declared (2026-09-16, re-measured 2026-09-18)

`fhir_chems.py` renders the pre-alert as a **CH EMS document** (`ch.fhir.ig.ch-ems` 2.0.0-ballot, the IVR / HL7
Switzerland mission-protocol format, eCH-0207; STU ballot open until 2026-09-30): a `document` Bundle with a
CHEmsComposition in `status: preliminary` (the pre-alert precedes the handover), with a version-independent
`Composition.identifier` and `confidentiality` N + the CH Core EPR confidentiality extension (0.6.1), the mandatory *mission* section
(CHEmsEncounter with the mission number, the alarm time as `period.start` — required, never defaulted — IVR
mission-time observations, urgency and mission type only when given), *findings* (heart rate and blood pressure
in the fixed "Circulation" sub-section, AVPU in "Disability" only when the patient is alert — V/P/U are not
distinguishable from OMEGA's input, so no code is invented; respiratory rate, SpO2 and temperature as entries of
the findings section itself, because CH EMS has no profile for them), *handover* (patient status priority = START
colour as SNOMED, destination organisation) and an *annotation* section carrying the NEWS2 risk assessment, the
interaction flags and the OMEGA Provenance. **Not in the IG, exported on purpose and disclosed here:** the
multi-patient event id as an additional Encounter identifier typed by an OMEGA code system (CH EMS issue #56,
open — our proposal, not an IG element).

Evidence semantics (CH EMS document): the ledger anchor is a Provenance *entity* (a digest is never labelled a
signature; the plain R4 export of `fhir_export.py` keeps its legacy `Provenance.signature` carrier for 0.6.x consumers); a real
record-bound Ed25519 signature (the OMEGA audit record, FORMAT.md) travels as entities too — record digest,
signature, verifying key — never as a FHIR `Signature`, which by definition covers the Provenance targets and would
falsely claim to cover this JSON; it adds `Composition.attester` — the step the eCH-0207 use cases describe as the crew "signing the document".

Measured with the official HL7 validator 6.10.4 against `CHEmsDocument` (`python3 chems_validate.py --strict`,
also a CI job with a positive control that must fail) on **two** documents — the full pre-alert and the earliest
minimal one (alarm time only, one vital, patient not alert, no colour, no destination): **0 errors** each (8 and
6 warnings); the same two documents on ahdis's public Matchbox server (`test.ahdis.ch/matchboxv3`, ch-ems
2.0.0-ballot loaded, 16/09 and 18/09/2026): **0 errors** each (7 and 4 warnings) — note that Matchbox does not
report display-name mismatches (measured with a positive control, see EVIDENCE.md), so it corroborates structure and
bindings, not display names. Every warning is explained (measured 2026-09-18 by
declaring the EPR profiles on our resources, `examples/chems_conformance/rerun_20260918/abl-omega-minimal-epr-profiles*`):
the three `ch-ems-epr-*` warnings are the CH Core *EPR* profiles not being met — the anonymous patient has no
identifier, name, gender or birth date (by design: identity is joined in the hospital); since 0.6.1 the Composition
carries `identifier` and `confidentiality` (required by `ch-core-composition-epr`, not by CH EMS), so its warning
remains for one reason only — the subject must be a `ch-core-patient-epr` — and the document-level warning follows
from the Composition one. The other warnings: the OMEGA code system is not
resolvable by the terminology server, and the IVR identifier type `MN` is not in the HL7 identifier-type value set
(a property of the IG). What is **not** exported because OMEGA does not compute it:
NACA, GCS, diagnosis, procedures. Organisations need a real 13-digit GLN (format checked, registration not). The
OperationOutcome files of both validators, for our two documents and for the IG's four published examples, are in
`examples/chems_conformance/` (see its EVIDENCE.md).

**Reading CH EMS documents from anyone** — `chems_ingest.py` (`python3 chems_ingest.py doc.json [--validate]
[--eta 67] [--anchor OPERATOR]`): strict load (duplicate keys refused), document rules (Composition first, every
reference resolvable — FHIR bundle resolution, relative references against RESTful `fullUrl`s as in the IG's own
published examples, which are read end to end — every entry reachable), vitals by CH EMS codes with UCUM units checked (never converted),
AVPU/GCS/NACA/cardiac arrest/priority/mission times, only for observations whose `subject` is the Composition's
subject (others are ignored and reported), the latest aware instant winning among duplicates (reported), then the
OMEGA scoring engine on the document's own vitals: without an age or without AVPU/GCS the document is **not**
scored (nothing is assumed in the unsafe direction; pass `--eta` from the radio call), and because CH EMS carries no
supplemental-oxygen observation the NEWS2 is reported as a **lower bound**. Duplicate keys are refused when the
input is a file or bytes; a caller passing an already-parsed dict has collapsed them itself (said in `avvisi`). `--anchor` records the document's SHA-256
in the signed, hash-chained audit ledger that the four independent verifiers check offline: the evidence layer
CH EMS does not have, on top of the format it does (the audit line holds the digest, the mission number — an
operational quasi-identifier towards the ePCR, no patient data — the IG version and the validator counts). Drug
interactions in CH EMS documents (0.7.0): MedicationStatement/MedicationAdministration of the Composition's subject are
resolved by Swiss GTIN → ATC (official Swissmedic list) or trade name; the check runs on recognised drugs only and the
unrecognised and discarded ones are listed. Real data: the four documents published by the IG
are read end to end (they hold GCS, NACA, blood pressure and mission times but not the NEWS2 vital set, so they are
reported as not scorable with the missing inputs named).

## Privacy by design

Vitals live in memory for the care flow only. The provenance ledger stores **digests,
never health data**. The FHIR bundle is anonymous (age only). Confirmation signatures
bind operator, time and meaning to the record — accountability without surveillance.

## Interoperability & the 2029 horizon

The EU **EHDS regulation** (in force 26 Mar 2025) makes primary health-data exchange
mandatory from **March 2029** — this project speaks FHIR R4 today for that reason, and
exports ATMIST because that is the handover language emergency departments already use.

## Roadmap honesty

What this needs next is not more code: it is a **measured pilot** (pre-registered
endpoints, published results) with a clinical partner. See `GRANT_APPLICATION.md` and
`ONE_PAGER_CLINICO.md`. Automatic ECG interpretation is deliberately **absent**:
without clinical validation it would be an overclaim.

## Intended use and run profiles (0.7.0; default `comunicazione` since 0.7.2)
`INTENDED_USE.md` states what the software is for and for what it is not, with the Swissmedic Merkblatt on
software (BW630_30_007 v3.0) and EU MDR Rule 11 as references. Two profiles, chosen at start-up with
`OMEGA_PROFILO`: `comunicazione` (**the default since 0.7.2**: vitals as sent, identity, signed evidence, CH EMS
document via the library — **no score, no recommendation**, the scoring engine is not executed and the fields are listed
as not computed in every pre-alert record) and `punteggi` (opt-in, `OMEGA_PROFILO=punteggi`: scores shown as supporting
information; regulatory exposure declared, no conformity assessment done). The CLI (`ambulanza_cli.py`) and the
library keep computing scores when called directly: the profile governs the server, which under `comunicazione`
rebuilds every pre-alert from the validated inputs and ignores any decisional field a client sends (`/prealert`
is routed to `/valuta` for the same reason). The active profile is printed at start-up. Also new in 0.7.0:
per-operator tokens (`POST /operatori`, admin token only; `OMEGA_REQUIRE_OPERATOR=1` refuses clinical events
without an authenticated operator), the optional AES-256-GCM board journal (`OMEGA_BOARD_STORE`), the receipt
endpoint for third-party ePCRs (`POST /chems/ingest`, `POST /chems/verifica`), and Swissmedic-backed drug
recognition by GTIN in CH EMS documents.

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ omega-health-companion
```

Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments verified by pip. All documented `python3 <file>.py` commands keep working unchanged from a clone.

## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/omega-health-companion/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with EMS services and hospitals that want the pre-alert as signed, verifiable evidence rather than a message. Write with the use case; the answer says what is measured and what is not.
- **Licence**: AGPL-3.0-or-later: study, test and use it freely; a service built on it must share its changes; a **commercial licence of the same code** is available from the author for organisations that cannot adopt AGPL.
- **Citation**: DOI [10.5281/zenodo.22539173](https://doi.org/10.5281/zenodo.22539173) (Zenodo, concept DOI: always the latest version).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.
