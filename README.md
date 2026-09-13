# OMEGA Health Companion — open pre-hospital alerting with incorruptible evidence

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539173.svg)](https://doi.org/10.5281/zenodo.22539173)

**Ambulance → hospital pre-alert engine, open and self-hosted.** During transport it
computes **validated clinical scores** (NEWS2 · RCP 2017, BE-FAST, qSOFA · Sepsis-3,
CDC/ATLS trauma criteria, ERC arrest logic, ESC STEMI pathway), screens for known
severe drug interactions, and produces **one integrated pre-alert** so the emergency
department prepares the right team *before* arrival. Every pre-alert is anchored to an
append-only **SHA-256 hash-chain (digest only — no health data on disk)** and every
issue/confirmation can carry a **record-bound electronic signature** (who issued, who
took charge, when).

**License:** AGPL-3.0-or-later · **Language:** Python 3, stdlib only (`cryptography`
optional for the signature bridge) · **Author:** Roberto Locatelli, 2026

## Honest scope (read this first)

- **Not a medical device.** Not certified, not clinically validated. It computes
  *recognised standard scores* (arithmetic from published tables — no invented
  algorithms, no AI diagnosis) and communicates them. **The physician decides.**
  One **declared deviation** from the RCP NEWS2 escalation bands: a single parameter scoring 3
  is escalated to MEDIUM here (RCP: low-medium), stated in every output as
  `deviazione_dichiarata`; the 587-vector certificate covers the arithmetic, not the bands.
- Real clinical use requires a supervised pilot and the applicable regulatory path
  (EU MDR). This codebase is the *engine* for such a pilot.
- Adult patients only: for age < 16 the system **refuses to score** (fail-closed;
  adult scores are not validated in children) instead of producing a wrong number.
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
| `fhir_export.py` | Pre-alert → **FHIR R4 Bundle** (LOINC-coded vitals conformant to the R4 vital-signs profiles — BP as the 85354-9 panel with diastolic `dataAbsentReason` when not measured, SpO2 as 2708-6 + 59408-5; 0 structural errors on both HAPI `$validate` and the HL7 `validator.fhir.org`, re-checked 2026-09-11 — RiskAssessment, Provenance carrying the ledger hash) — validated with **0 errors** against the public HAPI FHIR validator; ATMIST handover; ECG attachment by SHA-256 (never auto-interpreted) |
| `ambulanza_cli.py` | Field CLI: raw vitals in, computed pre-alert back; honest fallback message if the server is unreachable |
| `audit_bridge.py` | **Optional** bridge to a 21 CFR Part 11-grade audit engine (signed audit trail, signatures bound to records with meaning). Degrades honestly to "base" level when the engine is absent — the engine is not part of this repository |
| `companion_seed.py` | Citizen-facing claim verification seed (informative only) |
| `mission_case.py` | **Mission case file**: declarative FSM (ALLERTA→VALUTAZIONE→TRASPORTO→CONSEGNATA→CHIUSA, +ANNULLATA), SHA-256 hash-chained append-only ledger under an exclusive file lock, digests-only (no PHI), monotonic-clock guard, tamper → pack refused. Optional private case-engine adds an independent double replay; degrades honestly to "fascicolo-locale" (verified: same 17 tests pass with and without the engine) |
| `prealert_criteria.py` | **RCEM/AACE 2025 pre-alert criteria** (adult thresholds adapted from NEWS2, paediatric table by age band adapted from PEWS, 16 specific conditions, JRCALC high-risk sepsis markers) transcribed from the July 2025 UK national guideline (PDF SHA-256 pinned) — says *whether* the guideline indicates a pre-alert and *why*; "headline + ETA first, then ATMIST, ≤60 s" message. Declared scope: no BP trend, no "new for patient" GCS; children get *criteria*, never an adult score |
| `verbale_probatorio.py` | **Evidentiary record of the pre-alert** ("recorded line" made verifiable): signed ED *receipt* (who answered, role, response requested vs enacted, reason-by-digest if different, latency), per-pre-alert *verbale* that re-verifies every signature against the operator's registered key and the signed hash chain, detects tampering, re-signing and deletions, optional **RFC 3161 timestamp** on the verbale digest with CMS-signature verification and persisted bytes — level declared (`rfc3161-non-qualificata`: a QTSP on the EU Trusted List is needed for an eIDAS *qualified* timestamp) |
| `coordinamento.py` | **What the field leaders do, done the OMEGA way** (compared online 2026-09-13 with Pulsara, Twiage, corpuls.mission, NIDA): patient type → team to alert (from the computed pathways and the 2025 conditions, closed vocabulary), en-route ETA/position updates, two-way crew↔ED messages, ECG/scene-photo/document attachments (magic-byte checked), "close the loop" clinical outcome, QA/QI metrics (latency, alternative responses, over/under-triage proxies), major incidents with several patients. Every event is signed; free text and bytes live only in memory with the board TTL; the ledger holds digests and closed values |
| `test_input_types.py` | **31 tests** (22 distinct methods, 4 API cases re-run in three server contexts) — the hostile-input red-team cases of 2026-09-11 in three rounds (string flags in vitals, `clinica` and FAST signs, boolean vitals, missing/invalid age, malformed drug list, client-computed pre-alert, note persistence, board retention); 14 of them red on the code they were written against, the rest positive controls; unit + end-to-end over HTTP |
| `test_health.py` | **20 tests**: unit benches (positive + null controls, incl. a bench-of-the-bench that must fail) + end-to-end over real HTTP (auth rejected, °F detected, ledger chain verified, CLI against live server) |

## Quick start

```bash
python3 test_health.py                  # 20 tests (unit benches + E2E over localhost)
python3 test_mission_case.py            # 17 tests — mission case file (both engine levels)
python3 test_input_types.py             # 31 tests — hostile input types (red-team 2026-09-11, three rounds)
python3 test_news2_certificate.py       #  4 tests — NEWS2 certificate
python3 test_prealert_2025.py           # 49 tests — RCEM/AACE 2025 criteria at the boundaries, ED receipt, verbale, tamper/re-sign/deletion detection
python3 test_coordinamento.py           #  4 tests — patient types, incidents, ETA/position, messages, attachments, outcomes, metrics, expiry (end-to-end)
# 125 tests in total; the same six files run in CI on every push, with and without `cryptography`, never with the private engine
# HEALTH_TSA_URL=https://freetsa.org/tsr HEALTH_TSA_CAFILE=cacert.pem python3 test_prealert_2025.py   # + 2 opt-in network tests: real RFC 3161 timestamp, trust chain, wrong CA refused
python3 team_comms.py 8097              # ED board on http://127.0.0.1:8097/
python3 ambulanza_cli.py --rr 28 --spo2 89 --o2 --sbp 85 --hr 135 --non-alert \
        --temp 39.4 --eta 67 --arrivo 8 --farmaci warfarin aspirina
```

A systemd user unit is provided in `deploy/` (loopback by default; put TLS in front
before exposing beyond localhost).

## Legal-grade evidence of the pre-alert (2026-09-13)

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
closed-vocabulary or a digest: no free text and no health data on disk.

## Compared with the field (read online on 2026-09-13)

| Capability | Pulsara / Twiage / corpuls / NIDA | OMEGA Health Companion |
|---|---|---|
| Pre-arrival notification with vitals, ETA | yes | yes (`/valuta`), plus the **national 2025 criteria** saying *why* |
| Patient types → team | Pulsara: 12 patient types | `tipo_paziente` / `team_da_allertare`, derived, closed vocabulary |
| ECG / photo / document sharing | yes | `POST /allegato/<id>` — bytes in memory (TTL), digest in the signed ledger, magic bytes checked |
| GPS / ETA updates en route | yes | `POST /posizione` — exact position in memory, only ETA + a digest of the position in the ledger |
| Two-way secure chat | yes | `POST /messaggio` — text in memory, digest signed |
| Outcome feedback ("close the loop") | Pulsara | `POST /esito` — closed vocabulary, signed |
| QA/QI performance data | Pulsara, corpuls.web ANALYSE | `GET /metriche` — aggregates, no identifiers |
| Mass-casualty / multi-patient | Pulsara | `POST /incidente`, `GET /incidente/<id>`, START tags per patient (`POST /triage`, signed, re-triage allowed) |
| ED status / divert | Pulsara, Twiage | `POST /stato_ps` — accetta / saturo / dirotta, signed, returned with every pre-alert |
| Escalation when nobody takes the call | Pulsara | `da_escalare` in `GET /metriche` (no receipt after 120 s) |
| **Evidentiary record of the pre-alert** (who said what, who answered, chain, timestamp) | none documented | `GET /verbale/<id>` — this is the difference |
| Audio/video calls, live 12-lead telemetry | yes | **not done**: infrastructure, not evidence; integrate with those tools instead |
| Patient identity lookup / pre-registration | Twiage | **not done by design**: PII-free |
| NEMSIS export | US products | **not done**: FHIR R4 is the European road |
| MDR certification | corpuls.mission LIVE | **not yet**: pilot + class IIa file are the roadmap |

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

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ omega-health-companion
```

Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments verified by pip. All documented `python3 <file>.py` commands keep working unchanged from a clone.
