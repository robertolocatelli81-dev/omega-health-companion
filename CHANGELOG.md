# Changelog

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
