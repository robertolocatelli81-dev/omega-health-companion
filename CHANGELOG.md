# Changelog

## 2026-09-13 — from pilot to product: national pre-alert criteria and legal-grade evidence (v0.3.0)

Direction set by the author on 2026-09-13 («evolve it from pilot study to real software, looking at
the future and at legal guarantee in healthcare»), after an online comparison with the field (Pulsara,
Twiage, corpuls.mission, NIDA, WebEMS): none of them makes the pre-alert itself *evidence*.

- **`prealert_criteria.py`** — the RCEM/AACE July 2025 UK national pre-alert guideline transcribed as
  data (PDF SHA-256 pinned): adult physiological thresholds (RR ≤8/≥25, SpO2 on O2 ≤91 % or ≤83 %
  hypercapnic, SBP ≤90, HR ≤40/≥131, GCS <13), the paediatric table by age band (RR/HR per band,
  SpO2 <91 % on air, CRT ≥3 s, GCS <13, ≥38 °C under 3 months), the 16 specific conditions and the
  JRCALC high-risk sepsis markers (valid only with a history of infection). Output says whether a
  pre-alert is indicated and by which criterion; "heads-up" calls are refused by design. The message
  follows the prescribed order: headline concern and ETA first, then ATMIST, with a ≤60 s estimate.
  Declared out of scope: BP trend, "new for patient" GCS. **Children get pre-alert criteria, never an
  adult score** — the <16 refusal of NEWS2 stands.
- **Integrated engine**: `criteri_prealert_2025` in every pre-alert (adult and paediatric); conditions
  derived from the existing pathways (arrest, STEMI, trauma team, FAST+) merge with those declared by
  the crew (`condizioni`, type-strict, unknown keys refused); an isolated 2025 criterion with a low
  NEWS2 raises priority to MEDIUM with a coherent action.
- **`verbale_probatorio.py`** + `POST /ricezione` + `GET /verbale/<id>[?marca=1]` — the ED receipt is
  signed (closed vocabulary for role and responses; reason for an alternative response mandatory and
  stored by digest); the per-pre-alert record re-verifies each signature from the canonical record,
  detects tampering, reports latency; optional RFC 3161 timestamp on the record digest, verified
  (`Granted` + message imprint), level declared as non-qualified unless a QTSP is used.
- **Pre-push review by three independent models (same day), each finding verified on the code and
  fixed, with a test that is red on the previous code:** the JRCALC "needs oxygen" sepsis marker fired
  on the patient who *held* the target on oxygen and not on the one who did not (now: on oxygen =
  marker, "still below target" stated); `verifica_marca` accepted a fabricated timestamp reply that
  merely printed `Granted` (now the CMS signature of the token is verified with the embedded certificate,
  and the TSA chain with `HEALTH_TSA_CAFILE`); a ledger row could be rewritten and re-signed with an
  attacker's key because the public key was taken from the row itself (now every signature is checked
  against the operator's *registered* key, `.audit_keys/fb-<op>.pub`, exported in the verbale);
  deleting a row was invisible (now every row carries a signed `prev_sha256`; the verbale verifies the
  chain over the whole ledger — tail truncation remains a declared limit covered by the persisted,
  timestamped verbale); a child with GCS 8 or CRT 5 s and normal RR/HR got "no pre-alert" because
  `gcs`/`crt_sec` never reached the paediatric criteria (now via `clinica`); `/valuta` did not pass
  `condizioni`, `eta_mesi` or `sepsi`; the sepsis function was never called by the engine; "GCS <13 new
  for patient" fired on chronic deficits (now `clinica.gcs_abituale` excludes them); SpO2 in air (adult)
  and on oxygen (child) were silent (now declared in `non_valutato`); derived conditions (CDC field
  triage for MTTT, FAST+ without thrombolysis window) now say how they were derived.
- **Second review round (same three models), again verified and fixed:** `verified` on a timestamp
  ignored the TSA trust chain (a token from a self-signed TSA would have been "verified") — now
  `verified` is True only with the CMS signature *and* the chain to the CA given in `HEALTH_TSA_CAFILE`,
  None ("coherent, TSA not trusted") without a CA, False with a wrong CA (measured: freeTSA root CA →
  OK, a self-signed "TSA-FALSA" → refused); operators with keys created before this release had no
  registered public key (now derived from the existing key on first use); `sepsi` was silently ignored
  under 16 (now declared as not applicable, with a paediatric sepsis pathway hint); `eta_mesi` accepted
  with `eta` ≥ 1 (now refused as inconsistent); the Part 11 trail reader used the wrong record layout
  (now the verbale lists the engine's records and, if the engine refuses a corrupted trail, says so
  instead of raising). Declared limit written into the verbale: the key registry lives on the same host
  as the ledger — a third party must receive it out of band or rely on the timestamped verbale.
- **Tests**: 46 new (boundaries of every threshold, every paediatric band, hostile types, sepsis needs
  infection history, receipt vocabulary, tamper / re-sign with foreign key / row deletion detection,
  legacy-key and legacy-row boundaries, fabricated timestamp reply refused, persisted verbale,
  end-to-end over HTTP, bench-of-the-bench with a deliberately broken threshold) + 2 opt-in network
  tests with a real TSA (green against freetsa.org with its root CA on 2026-09-13; tampered token and
  wrong CA refused). 118 in total, in CI with and without `cryptography`; 10 consecutive full runs green
  in the public configuration.

## 2026-09-11 (third pass) — what the second independent verification still found

An independent verifier re-ran everything on the *public* configuration (anonymous clone, no private
engine, with and without `cryptography`) after the two passes below. It found — and this release fixes:

- **The string-truthiness class was closed on vitals only.** `clinica: {"ecg_stemi": "no"}` still
  produced HIGH priority with "STEMI confirmed, bypass ED"; `{"meccanismo_maggiore": "no"}` activated
  the trauma team; `{"dolore_toracico": "no"}` the cardiac path. Now every `clinica` flag and every
  `fast_segni` sign must be a JSON boolean, `gcs` an integer 3–15, unknown keys are refused, and
  `eta_arrivo_min` must be a number in 0–600 — each a named structured refusal.
- **`POST /prealert` accepted a client-computed pre-alert** (two keys checked): a fabricated record with
  age 3 and a patient name landed on the board and in `/api/board`, bypassing the paediatric gate. The
  server is the only source of truth: the endpoint now recomputes from `vitali`/`eta`/`farmaci` exactly
  like `/valuta` and ignores every computed or unknown field.
- **The free-text confirmation note was persisted in clear** (`audit_locale_ledger.jsonl`, Part 11
  trail) — a name and a fiscal code typed by the ED were found on disk while PRIVACY promised no
  health data at rest. Only the note's SHA-256 and length are recorded now; the text lives on the
  in-memory board only.
- **Board retention ran only on publication**: an expired record was still served by `/fhir` until
  the next POST. Expiry now runs on every read (`/`, `/api/board`, `/fhir`, `/atmist`).
- **`test_health.py` failed 2/20 in the public configuration with `cryptography`** because the
  `firma-locale` audit level was not modelled; CI passed only because it never installed
  `cryptography`. Tests model all three levels; CI runs a matrix with and without `cryptography`,
  never with the private engine.
- BE-FAST: `balance`/`eyes` were accepted by the API and CLI and silently dropped before scoring
  (the posterior circulation the README promised). They now reach the score.
- Malformed-JSON responses no longer name Python exception classes.
- **Administrative audit events separated from clinical confirmations** (found by the pre-push
  review of this very fix): `/rimuovi-nota` and `/ruota-token` reused `registra_conferma`, so they
  were recorded as "presa in carico" with a RESPONSIBILITY signature — a false meaning — and, after
  the digest change above, their administrative reason would have been hashed away. They now go
  through `registra_evento_sistema`: action `rimozione_nota` / `rotazione_token`, the operator's
  reason in clear (it is the justification Part 11 requires, not health data), the removed clinical
  note bound by digest, the previous value recorded as §11.10(e) demands, AUTHORSHIP signature.
- `vitali.bpco_scala2` (optional SpO2 scale-2 flag) reached `news2()` unvalidated: `"no"` scored as
  *true* and moved NEWS2 from 2 to 5 (LOW → MEDIUM). Found by the pre-push verification of this very
  release. Now a JSON boolean like every other flag, and unknown keys in `vitali` are refused by name.
- 31 regression tests in `test_input_types.py` (22 distinct methods), 14 red on the code they were
  written against. 72 tests total,
  green in all three configurations (bare, `cryptography`, private engine).
- Released as **v0.2.1** with a wheel: until now the only installable artifact (0.1.2) still carried
  the clinical inversion fixed in the morning.

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
