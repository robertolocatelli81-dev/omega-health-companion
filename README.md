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
| `test_input_types.py` | **13 tests** — the hostile-input red-team cases of 2026-09-11 (string flags, boolean vitals, missing/invalid age, malformed drug list), each red before the fix; unit + end-to-end over HTTP |
| `test_health.py` | **20 tests**: unit benches (positive + null controls, incl. a bench-of-the-bench that must fail) + end-to-end over real HTTP (auth rejected, °F detected, ledger chain verified, CLI against live server) |

## Quick start

```bash
python3 test_health.py                  # 20 tests (unit benches + E2E over localhost)
python3 test_mission_case.py            # 17 tests — mission case file (both engine levels)
python3 test_input_types.py             # 13 tests — hostile input types (red-team 2026-09-11)
python3 test_news2_certificate.py       #  4 tests — NEWS2 certificate
# 54 tests in total; the same four files run in CI on every push (.github/workflows/tests.yml)
python3 team_comms.py 8097              # ED board on http://127.0.0.1:8097/
python3 ambulanza_cli.py --rr 28 --spo2 89 --o2 --sbp 85 --hr 135 --non-alert \
        --temp 39.4 --eta 67 --arrivo 8 --farmaci warfarin aspirina
```

A systemd user unit is provided in `deploy/` (loopback by default; put TLS in front
before exposing beyond localhost).

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
