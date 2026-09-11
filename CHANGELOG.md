# Changelog

## 2026-09-11 (second pass) — claim-by-claim verification against the public repository

- **FHIR R4 vital-signs profiles.** The Bundle had 0 errors on HAPI `$validate` but **6 structural
  errors on the HL7 `validator.fhir.org`**: a lone LOINC 8480-6 Observation violates `bp|4.0.1`
  (panel 85354-9 with systolic + diastolic components required) and 59408-5 alone violates
  `oxygensat|4.0.1` (2708-6 required). Now: BP is the 85354-9 panel with the systolic component and a
  diastolic component carrying `dataAbsentReason: not-performed` when not measured (pre-hospital
  reality, allowed by the profile); SpO2 is coded 2708-6 + 59408-5. Re-validated: 0 structural
  errors on both validators (the HL7 validator's own terminology-server timeouts excluded).
- **Board retention.** The in-memory board kept vitals for as long as the process lived. Records
  older than `OMEGA_BOARD_TTL_H` hours (default 24) now lose their clinical payload (id, time and
  digest provenance remain); `/fhir` and `/atmist` answer 410 for them; the page renders them as
  SCADUTO. The ledger was already digest-only.
- Texts realigned to the data: ONE_PAGER said FAST (it is BE-FAST) and "5 pathways" (6); the
  Pulsara evidence is BMJ Open Quality 2022, Bladin et al. (Ambulance Victoria/Monash), not Duke;
  "no competitor offers this" → "none of the competitors examined documents it" (a universal
  negative was not a measured claim); contact placeholders filled; the NEWS2 escalation deviation
  (single parameter = 3 → MEDIUM) is now stated in the README, not only in the JSON output.
- `pyproject`: version 0.2.1 (the tag v0.2.0 had shipped with 0.1.2 inside), licence
  `AGPL-3.0-or-later` as everywhere else; the optional Part 11 engine path is configurable
  (`OMEGA_PACKAGE_DIR`) instead of hard-coded; local audit ledger and operator keys ignored by git.
- SBOM + CRA evidence pack attached to every release (v0.1.0, v0.1.2, v0.2.0 lacked them).

## 2026-09-11 — input-type hardening (clinical safety fix)

Found by an adversarial review of this public repository (four independent passes: objective
gate, exploit attempts against the running API, framing review, claim-by-claim verification),
run because the repository is under evaluation by funders. Measured before the fix, on
`POST /valuta` with a valid token:

- `alert_coscienza: "no"` (a JSON **string**) was read by its Python truth value → *true* →
  the patient scored as **alert**. A clinical inversion.
- `su_ossigeno: "false"` (string) → *true* → scored as a patient on oxygen.
- `rr: true` (JSON boolean) → `1.0` → respiratory rate 1/min → priority MEDIUM from a flag.
- `eta` missing → the paediatric gate was skipped and an **adult** score was produced (fail-open).
- `eta: "4"` → a Python `TypeError` message was returned to the client; `eta: -3` → paediatric path.
- `farmaci: [{...}]` → unhandled `AttributeError` in the handler; the connection was dropped.

Fix (`barella_prealert.py`, `ambulanza_intelligente.py`, `team_comms.py`): clinical flags must be
JSON booleans; numeric vitals must be JSON numbers (booleans and strings rejected; NaN/Inf rejected);
age is required and must be a number in 0–130; the drug list must be a list of strings; every case is
a **named**, structured refusal (`NON_VALUTABILE_DATI_INVALIDI` with `problemi_dati`, or a 400 with
our own message) — never a score, never an exception, never an internal error text. Regression suite
`test_input_types.py` (12 tests, each red on the previous code). CI added (`.github/workflows/tests.yml`),
committed build artefacts (`dist/`, `*.egg-info`) removed.

What did **not** change: the ledger was and is digest-only (verified: no vital sign or age is
persisted), token authentication held, oversized payloads were already refused, NaN/Inf vitals and
paediatric ages were already refused.
