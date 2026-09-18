# Changelog

## 0.7.2 — 2026-09-18 — default profile is `comunicazione`

- **Breaking, on purpose (author's decision after the whole-product judgement):** the server's default `OMEGA_PROFILO` is now
  `comunicazione`. A standard installation computes and shows no score, priority, recommendation, pathway, drug warning or
  patient type; it validates inputs, shows vitals as sent and records who sent what and when in the signed ledger (the CH EMS
  document is a library function, `fhir_chems.prealert_to_chems_document`, in both profiles). Scores return only with `OMEGA_PROFILO=punteggi`, written in the organisation's configuration: activating
  an uncertified decision-support function (EU MDR Annex VIII Rule 11 / MepV exposure) is an explicit act, never a default.
  0.7.1 deployments that relied on scores must set the variable. The library is unchanged (it computes when called); the
  CLI is a client of `/valuta` and never computed anything — the earlier README sentence "the CLI keeps computing scores"
  was false and is corrected in this release (found by Opus 5 in round 4, reading the CLI source instead of the README). Tests of the `punteggi` path set the profile in `setUpModule` and restore it in `tearDownModule` (explicit
  assignment, so an `OMEGA_PROFILO` exported in the environment cannot change what they test — measured: with `setdefault`
  and the variable exported to `comunicazione`, 5 files failed; and not at import time, because `unittest discover` imports
  every file before running any — measured: with a module-level set plus restore, `test_coordinamento` ran under the default
  and failed). CI now also runs the suite collected in one process. The profile tests cover the default: the end-to-end test now posts an adult, a 3-year-old
  and a known drug interaction, then scans the board, metrics, incidents, page, FHIR export, ATMIST and CH EMS document for
  every decisional key (each `avvisi` occurrence must be empty, `tipo_paziente` null at any depth, no nitrate text). Positive
  controls: the scanner self-checks in code on an injected key and an injected warning, and by hand a `"priorita"` added
  to the comunicazione pre-alert and a nested `trauma_team` added to `/metriche` were both caught before the code was
  restored; the journal restore test restarts with the variable absent. Under this profile the paediatric gate has nothing to
  guard (no adult score is ever computed) and a child's vitals are validated like any other input. Review of the diff by
  Gemini Pro, Opus 5, Sonnet 5 and Haiku 4.5, four rounds: five round-1 findings were false against the code (journal restore
  and `tipo_paziente` were already gated, the engine branch precedes the engine call, `/prealert` recomputes, CI runs each
  test file in its own process) and are recorded as such; the true ones are in this entry.
- **Round 2 (Opus 5) under the default, all measured and fixed:** the incident summary (`/incidenti`, `/incidente/<id>`)
  emitted `"priorita": None` and `"tipi": None` per pre-alert — a decisional key even if empty; now a comunicazione record
  carries neither (only `profilo`). The input contract of the comunicazione validator was stricter than the engine's
  (`eta` integer 0–120, `eta_mesi` 0–24 without coherence check, 20 drugs of 80 characters): a 0.7.1 client sending
  `eta: 67.0` would have got a new 400; now the four limits are the engine's (number 0–130, months 0–11 only under one
  year, 100 drugs of 120 characters). Clinical inputs of the criteria engine (`clinica`, `fast_segni`, `condizioni`,
  `sepsi`) were dropped silently; they are now listed in `campi_ignorati`. `/metriche` reported over/under-triage proxies
  of 0 that could never be computed; they are `null` with a `NON_CALCOLATI` note when no pre-alert carries the 2025
  criteria. Board page footer, expired-card header (`NEWS2 —`) and the ATMIST I segment (`vedi percorsi`) were profile-blind;
  fixed and asserted. The end-to-end test now also creates an incident with a linked patient, posts an outcome, and builds
  the CH EMS document from every case. Round 3 (Gemini Pro): an expired pre-alert linked to an incident fell back into the
  `punteggi` branch of the incident row (`"priorita": "SCADUTO"`); the live profile is now passed to the summary and the
  test expires a linked patient and re-scans. Round 3 (Opus 5): the expired board card under the default showed `None`
  instead of the retention notice; `campi_ignorati` is now generic (every request key the profile does not read, so a
  client-computed `NEWS2` is named too); blank drug strings are dropped; `avvisi` is no longer listed as "not computed"
  (it is present, always empty); the test scans assert HTTP 200 and real bodies, scan JSON text for every decisional token
  after removing the keys that legitimately list field names, pin the comunicazione pre-alert to an exact allowlist of
  keys, guard the engine's output against unclassified keys, prove the same three cases *do* leak under `punteggi`, and pin
  that the library computes regardless of the profile; CI also runs the suite with the variable exported as
  `comunicazione` and as `punteggi`. The token scan found one real collision: the CH EMS observation carrying the crew's
  START colour had the id `priorita-paziente` — an input, not a score — renamed `stato-paziente` (samples regenerated,
  validator_cli 6.10.4: 0 errors, `examples/chems_conformance/EVIDENCE.md`). Round 4 (Opus 5; Gemini Pro: no material
  issues): the CLI now prints the profile and the note under the default instead of silent nulls, and no longer sends
  top-level null keys; `campi_ignorati` counts only keys with a value and refuses malformed or more than 20 unknown key
  names (the name is echoed into the record and the journal: never free text; round 5: `fullmatch`, so a trailing newline
  does not pass either; round 6: `\A…\Z` anchors, `tipo_paziente` stripped from a restored pre-alert too although the engine never puts it there — it lives in the board record, where restore nulls it — and the restored shape is asserted against the allowlist; `/audit` is only the trail summary (level `base` in the test sandbox), so the two local ledgers are asserted structurally per record — every `emissione` carries exactly the pre-alert digest (64 hex) and the identity vocabulary word, every chain record has exactly its six keys with `payload: digest`, one record per anchoring POST, and the same read sees a further valid POST; positive controls by hand: an extra `priorita` field in the emission record and a non-hex value in the digest slot each made the test fail — and re-read after a refused request to prove nothing was anchored (round 7: a token scan of a digest-only ledger was a null test and is gone); a malformed key name inside `vitali` gives 400 and both ledgers are byte-identical before and after); the comunicazione pre-alert lists the same `campi_non_calcolati`, the same note and a
  `campi_ignorati` key whether fresh or restored; unknown keys *inside* `vitali` were already refused by name (measured,
  now guarded by a test); the CLI's own record is in the output scan and the local ledgers are asserted structurally (round 6 above);
  the scanner's positive controls are discriminating (a value-encoded score is invisible to the key scan and visible to
  the token scan; a histogram and the listing fields are not flagged); the end-to-end test also posts client-computed
  scores and runs the real CLI against the default server; the engine drift guard covers the invalid-data branch.
  200 tests. One flaky test fixed on the way: `test_bacheca_store` asserted that the 2-byte marker `H2` was absent from
  the encrypted journal file; a 2-byte sequence appears by chance in random ciphertext (1 red in 30 runs, measured) — the memory-only markers are now 18 to 33 bytes; the actual encryption control derives three persisted markers (8 to 22 bytes) from the store's own compact serializer (`bacheca_store.serializza`), asserts each is present in the bytes actually handed to `encrypt` (captured by patching `AESGCM.encrypt` itself and snapshotted before the restore) and absent from the raw file, asserts the memory-only markers absent from those same bytes (exclusion, not encryption), then writes one plaintext row into the same file and asserts the marker IS found — the positive control lives in the suite (round 10: a hand-written marker with spaces could never have matched compact JSON, a null control found by Opus 5; rounds 11–12: capture at `encrypt`, snapshot before restore, exclusion asserted on the plaintext; hand controls: no spy → the positive fails on empty bytes; a memory-only field persisted → the exclusion fails). 0 red in 40 runs of the final test body. The encryption was never at fault.
- **"Compared with the field" table re-read from primary sources (2026-09-18, quotes and digests in
  `gtm/health_070_20260918/competitors/` of the OMEGA repository, summarised here):** "Evidentiary record: none documented" was
  too strong — corpuls documents delegations «dreifach rechtssicher dokumentiert» plus audit logging of accesses, Pulsara a
  «time-stamped source of truth for each case»; the row now says what none documents (a record verifiable by a third party
  offline). "Escalation — Pulsara" was not a documented product feature (a regional advisory tells crews to phone after 60 s);
  "ED status — Twiage" is not stated on the TigerConnect page; rows that exist only in `punteggi` are marked. Every OMEGA cell
  was measured on the running 0.7.2 server in both profiles, and the CH EMS document built from a default-profile pre-alert
  validates with 0 errors (validator_cli 6.10.4). An adversarial pass by Gemini Pro on the comparison itself added what
  weighs against OMEGA: the competitors are end-to-end products with mobile apps and dispatch integration, OMEGA is a server
  with a board page and a CLI (two rows added, both "not done"); the competitors' records are legally usable, centralised
  records — ours is the offline-verifiable one, not the only valid one.

## 0.7.1 — 2026-09-18 — after Gemini Pro's whole-product judgement (8 dossiers + synthesis, 7/10)

- **Reverse proxy no longer leaks the admin token.** The board page injected the server token for "loopback" clients; behind
  nginx/docker/ngrok every external request is loopback. Now a request carrying any forwarding header (`X-Forwarded-For`,
  `Forwarded`, `X-Real-IP`, `X-Forwarded-Host`, `Via`) is never loopback: the page requires a token like any other client
  (tested).
- **Ledgers no longer read in full on every write.** The previous hash (local audit ledger, pre-alert ledger) is read from the
  tail of the file in O(1) (`audit_bridge._ultima_riga`, tested against the full read on 7 shapes including a 200 KB last line);
  it was O(N) in time and memory per write, growing forever.
- `team_token.txt` with permissions wider than 0600 is refused (named `PermissionError`), like the registry and the journal key.
- README: the heading "Legal-grade evidence" is gone; the section is "Evidence of the pre-alert: signed, hash-chained,
  verifiable offline". Same facts; server-generated keys are not legal-grade non-repudiation and the text below already said so.
- Judged, NOT changed in 0.7.1 (decisions for the author, recorded in gtm/health_070_20260918/judge; the default profile was
  then changed in 0.7.2): the declared NEWS2 deviation (single parameter 3 → MEDIUM, conservative direction) and the "lower bound"
  NEWS2 without an oxygen observation; per-operator keys on the server vs SSO/IdP identity; the seed drug-interaction table.

## 0.7.0 — 2026-09-18 — the gaps of the 18/09 maturity assessment, without changing what the product is

Independent assessment (Gemini Pro, 18/09/2026, facts measured): overall L2 "verified prototype"; operational readiness
L2 (state in RAM), clinical/regulatory L2, identity via shared token. Everything below closes a named gap; scores,
signed evidence and the CH EMS format are untouched.

- **Encrypted board journal, opt-in** (`bacheca_store.py`, `OMEGA_BOARD_STORE=<file.sqlite>`): pre-alerts, triage,
  receipts, outcomes, incidents and ED status survive a restart (a `dirotta` status comes back as `saturo` — the
  destination is never written — and is flagged for re-confirmation; a status older than the TTL is dropped). AES-256-GCM per entry (key file 0600, refused if wider),
  modified bytes = no data (AEAD; deletion or rollback of an entry is not detected — the signed ledger is the evidence). What today is promised "memory only" stays so: free text, confirmation notes, attachment
  bytes, exact coordinates, incident descriptions are NOT written and come back empty with `ripristinato_senza`
  listing them. TTL applies at restore; expired records lose vitals in the journal too. Without the variable: RAM only,
  exactly as before. Without `cryptography`: the store refuses to open.
- **Per-operator identity** (`operatori.py`): `POST /operatori` (admin token = the server token) creates an operator
  with a token shown once (only its SHA-256 on disk, 0600); `POST /operatori/revoca`. With `X-Omega-Operatore-Token`
  the name used for the Ed25519 signature is the registered slug: the body cannot impersonate *when an operator token is
  used*, and a declared name matching a registered operator is refused (403). The pre-alert response (`/valuta`) carries
  `identita: autenticata | dichiarata`. Pilot mode `OMEGA_REQUIRE_OPERATOR=1`: clinical events without an authenticated
  operator get a named 403. Declared limit: service-level identity, not legal non-repudiation (eID/QTSP not done).
  Declared names that slug to `admin`, `anonimo` or `sistema` are refused (403 "nome riservato al sistema"): they are
  the system signers. The `ingest_chems` ledger rows changed shape: `target` is now `chems/<sanitised mission id>-<8 hex
  of its sha256>` and `missione_numero` carries the same sanitised form, never the raw third-party string (0.6.2 rows
  keep their old shape).
  **Upgrade note:** the server token of a 0.6.x deployment is on every terminal; in 0.7.0 that token creates operators.
  Before enabling pilot mode rotate it (`POST /ruota-token`), keep the new one with the administrator only and give each
  terminal an operator token.
- **Receipt for third-party ePCRs** (`chems_receipt.py`, `POST /chems/ingest`, `POST /chems/verifica`): any CH EMS
  document in, a self-contained receipt out (exact-bytes SHA-256 anchored in the signed ledger, chain link, operator key);
  verification offline, three states OK / INCONCLUSIVA (valid signature, key not registered) / NON_VERIFICATA with the
  reason; digest always recomputed from the bytes. The document is not stored; the ledger holds digest, mission number,
  status, counts. Tested on the IG's four published examples.
- **Swiss medication codes** (`swissmedic_gtin_atc.py`, generated by `scripts/build_swissmedic_atc.py`): GTIN
  (`urn:oid:2.51.1.1`, as in the IG examples) → ATC from the official Swissmedic "Zugelassene Packungen" list
  (17,468 GTINs, Stand 31.08.2026, sha256 of the xlsx recorded; GTIN derivation 7680+authorisation+package+GS1 check,
  verified on the two GTINs of the IG examples). `chems_ingest` now reads MedicationStatement (active) and
  MedicationAdministration (completed/in-progress) of the Composition's subject, resolves GTIN → ATC → interaction
  class (or the Swiss trade name, `COMMERCIALI_CH`), runs the interaction check on recognised drugs only and lists the
  unrecognised ones (with their ATC when known) and the discarded resources (status, other subject, other encounter)
  instead of ignoring them. The ATC→class table covers the pairs in `INTERAZIONI` only (e.g. no ARBs, no
  amiloride/triamterene, no metformin combinations, no opioid ATCs outside N01AH/N02A/N07BC/R05DA04): those are reported
  as "fuori dalla tabella", not checked. Tramadol combinations (N02AJ13/14) carry the serotonergic class like tramadol. Bundle-1: Fentanyl (N01AH01), Nitrolingual
  (C01DA02), Aspirin Cardio — no severe pair in the table; positive control Nitrolingual + Viagra by GTIN → GRAVE.
- **Intended use and run profiles** (`INTENDED_USE.md`, `OMEGA_PROFILO`): in `comunicazione` the scoring engine is
  NOT executed (inputs are validated only) and no decisional field exists in the pre-alert (scores, priority,
  recommendation, pathways, flags, drug warnings); the FHIR R4 export, the CH EMS document and the ATMIST handover carry
  vitals as sent and no RiskAssessment (found by the new tests: they used to emit "priorità None · NEWS2 None"); `punteggi`
  (default) is unchanged and its EU MDR Rule 11 / MepV exposure is stated, with the Swissmedic Merkblatt
  BW630_30_007 v3.0 quoted for the "storage, archiving, communication" boundary.
- Server and operator tokens never start with `-` (a `token_urlsafe` value did, about once in 64, and `--token <tok>`
  on the CLI read it as an option: the e2e CLI test failed on that draw). With the private Part 11 engine the pre-alert
  and incident counters now continue from the engine trail after a restart (they restarted at 1).
- Four-mind review (Gemini Pro, Claude Opus, Sonnet, Haiku), three rounds on the diff, findings fixed before the tag: an operator token
  could rotate the admin token; the admin's own rotation self-locked in pilot mode; the confirmation form and the
  attachment upload bypassed pilot mode; drug warnings leaked into the communication profile; the journal kept outcomes
  after expiry and the free-text alternative destination; a journal write error dropped the connection after a signed
  publish; restored records ignored a changed profile; `/atmist` and the CH EMS document were profile-blind; receipts
  were looked up by document digest (spurious 503 on concurrent ingest); non-ASCII tokens raised.
- Tests: 195 across 15 files (new: test_bacheca_store, test_chems_receipt, test_operatori, test_profilo; test_chems_ingest
  +5), green in both CI configurations; the journal, receipt, operator-identity and profile end-to-end tests need the signed local
  ledger and are skipped (declared) in the bare-stdlib configuration.

## 0.6.2 — 2026-09-18 — public claims audited: test counts, opt-in TSA tests

- No code change in the product. Every checkable statement in the README was re-measured on 2026-09-18 and three were
  wrong and are corrected: the test counts (160 tests in the eleven `test_*.py` files CI runs, not "125 in six";
  `test_health.py` has 21, `test_input_types.py` 23 distinct methods), and "the same six files run in CI" (CI runs all
  eleven). The packaged README of 0.6.1 carried the old numbers; this release carries the measured ones.
- `test_prealert_2025.py`: the no-TSA null control removed `HEALTH_TSA_URL` from the process without restoring it, so the
  two opt-in network tests (real RFC 3161 timestamp from freetsa.org, trust chain) errored when run in the same process.
  Fixed with an isolated environment patch; re-run against the real TSA: OK.
- Re-measured and unchanged: plain FHIR R4 export validates with 0 errors on validator_cli 6.10.4 (R4 vital-signs
  profiles applied by the validator); all README links resolve; the pip index carries `#sha256=` fragments.

## 0.6.1 — 2026-09-18 — fail-closed signing, Composition identifier/confidentiality, exact EPR explanation

- **Audit bridge is fail-closed.** Without a signing engine (the private Part 11 engine or the local Ed25519 signer that
  needs `cryptography`) the bridge no longer records unsigned clinical events silently: `registra_conferma`,
  `registra_prealert`, `registra_evento_clinico` and the others raise `audit_bridge.FirmaNonDisponibile`, and
  `team_comms.serve()` refuses to start. The declared "base" (unsigned) level still exists, but only with the explicit
  opt-in `OMEGA_HEALTH_ALLOW_UNSIGNED=1` (CI's bare-stdlib job sets it; the `cryptography` job does not).
  `cryptography>=41` is now a declared dependency, so `pip install` brings the signer. Reason: the public statement
  "every event is signed" was true only when the optional dependency happened to be installed.
  `team_comms.serve()` and `chems_ingest --anchor` call `audit_bridge.esigi_firma_o_optin()` at start; the HTTP server
  maps `FirmaNonDisponibile` and signer `OSError`s to a named 503 (never a silent success or a dropped connection);
  opening an incident and publishing a pre-alert now sign BEFORE mutating the board or consuming a sequence id
  (previously an incident could exist in memory without its audit record if signing failed).
  Incident ids continue from the signed ledger after a restart (`audit_bridge.ultimo_id("incidente")`), as pre-alert
  ids already did. In the opt-in unsigned mode there is no trail to continue from: ids restart, and the banner says so.
- **CH EMS export: `missione.prealert_id` (opaque per-patient token) is now REQUIRED** and seeds `Composition.identifier`
  together with the mission number and the UTC-normalised alarm time (never the export instant), so two patients of one
  mission never share a Composition identifier, whether or not an OMEGA incident was opened (review finding). Callers
  of `prealert_to_chems_document` must pass it (breaking for 0.6.0 callers, on purpose: nothing is invented).
- **CH EMS document: `Composition.identifier` (version-independent, distinct from the per-instance `Bundle.identifier`)
  and `Composition.confidentiality` = N with the CH Core EPR confidentiality extension (SNOMED 17621005, no display —
  tx.fhir.org rejects "Normal" for de-CH, the error the IG's own examples show).** CH EMS does not require either;
  `ch-core-composition-epr` does. Measured: still 0 errors on validator_cli 6.10.4 and Matchbox, same 8/6 warnings; the
  `ch-ems-epr-composition` warning remains for one reason only, the subject must be a `ch-core-patient-epr`, which an
  anonymous pre-alert cannot satisfy (ablation in `examples/chems_conformance/release_0.6.1/`).
- README: the three `ch-ems-epr-*` warnings explained exactly (measured, not assumed); Matchbox caveat (it does not report
  display-name mismatches, shown with a positive control); incident descriptions live in process memory only.
- Conformance evidence re-measured on 2026-09-18 from scratch (validator re-downloaded, IG examples re-downloaded):
  `examples/chems_conformance/rerun_20260918/` + EVIDENCE.md — positive controls, ablations, why the IG's qa.html shows
  0 errors on examples that give 2 with the plain validator.

## 0.6.0 — 2026-09-16 — CH EMS document (Switzerland)

- `fhir_chems.py`: the pre-alert as a **CH EMS document** (`ch.fhir.ig.ch-ems` 2.0.0-ballot): `document` Bundle,
  CHEmsComposition `preliminary`, mission section with CHEmsEncounter (mission number, IVR mission-time
  observations, urgency), findings (heart rate, blood pressure, AVPU), handover (START colour as SNOMED patient
  status priority, destination organisation), annotation section with the NEWS2 RiskAssessment, flags and the
  OMEGA Provenance; the multi-patient event id as an additional Encounter identifier (CH EMS issue #56).
- `chems_validate.py` + CI job: conformance measured with the official HL7 validator 6.10.4 (0 errors, 8 explained
  warnings) with a positive control (a document without Composition must fail). `test_fhir_chems.py` (8 tests,
  null controls: no GLN, wrong check digit, unknown mission time, bad instant, bad colour → refused).
- Nothing invented: no NACA/GCS/diagnosis; organisations need a real GLN (format checked only); anonymous patient.
- Council of five (16/09/2026) on the module, findings fixed: the ledger anchor is a Provenance *entity*, never a
  `Signature` (a digest had been labelled "Author's Signature"); `Composition.attester` + `Provenance.signature`
  only with a real record-bound signature (fields validated strictly); the alarm time is required (`period.start`
  was defaulted to the export time); mission type is an input, not "primary" by default; `period.end` from the
  handover time; RR/SpO2/temperature are findings entries, not annotation entries; narrative texts follow
  `Composition.language`; the document identifier includes the status; the event id is shape-guarded.
  Second measured document: the earliest minimal pre-alert (found 2 real errors in the language-dependent LOINC
  display; fixed). Refuted by the synthesis on the IG package: findings/handover are 0..1, sub-section titles are
  fixedString English.
- `chems_ingest.py` + `test_chems_ingest.py`: reader, scoring and evidence anchoring for CH EMS documents from
  any producer (strict document rules, UCUM checked, honest scoring, signed audit record verified offline).
- Real data: the four documents published by the IG (Einsatzprotokoll 1/1b/2/2b) are read end to end; they use RESTful
  `fullUrl`s with relative references — the first reader refused them, so FHIR bundle resolution was implemented (a
  relative reference from a `urn:` fullUrl stays unresolvable, per spec). A protocol without NEWS2 vitals is reported
  as not scorable with the missing inputs named.
- Council round 2 on the reader (five minds), fixed: a Quantity without UCUM `system` or with a comparator is refused
  (it used to pass); observations are bound to the Composition's subject (others ignored and reported); duplicates are
  ordered by aware instant, not by string, and reported; the GCS unit check was tautological (any unit passed) — now
  `{score}`/`1` or `valueInteger`; consciousness is never assumed (no AVPU/GCS → not scorable) and the NEWS2 without an
  oxygen observation is flagged as a lower bound; partial birthDates handled and declared; the CLI reads the file once
  (no time-of-check gap between scoring, validation and anchor). Exporter: the verifying public key travels in
  Provenance, a signature without an anchored entry is refused, `period.end` must not precede the alarm.
- Council round 3: a newer but malformed observation now empties the slot instead of leaving the stale value; a date-only
  `effectiveDateTime` is not an ordering instant; every blocking reason for non-scorability is reported (none
  overwritten); a Composition subject that is not a Patient attributes nothing; the OMEGA record signature is carried
  as Provenance entities, not as a FHIR `Signature` (which would claim to cover the document's bytes).
- Council round 4: two same-code observations that cannot be ordered against each other yield NO value (Bundle order
  would be arbitrary) and say so; `effectiveInstant` is read; duplicate messages name what was kept and what was dropped.
- Council round 5: duplicate resolution rewritten as a two-pass selection on the whole set — the single most recent dated
  observation wins, a tie on the instant or undated-only duplicates give no value — proven order-independent over every
  permutation of the Bundle (test), which the incremental rule was not (two undated + one dated depended on the order).
- Council round 6: order independence confirmed by all five; residues measured and closed — a coding not in the value set
  placed before the valid one no longer loses the priority colour / AVPU / NACA; observation status `corrected` (R4)
  is read; the problem list is sorted and deduplicated so it is identical under any Bundle order.
- Council round 7: no positional fallback left — with no `Composition.encounter` the Encounter is used only if unique;
  a panel with two systolic components gives no value; a non-boolean cardiac-arrest value and a mission time without
  `valueDateTime` are reported instead of silently dropped.
- Council round 8: mission attribution is non-positional too — `Composition.encounter` must resolve to an Encounter (no
  fallback), conflicting MN or EVENT identifiers on the Encounter give no number and say so.
- Council round 9: the Encounter must belong to the Composition's subject (like every Observation); MN/EVENT identifiers
  without `value` are ignored and reported; EVENT conflicts are detected by (system, value) like MN.
- `examples/chems_conformance/`: public evidence — validator_cli 6.10.4 and Matchbox OperationOutcome files for our two
  documents and for the IG's four published examples (2 errors each on validator_cli: SNOMED display for de-CH), the
  5× real-online-data bench log, EVIDENCE.md with commands and versions; the IG-examples reader test now runs in CI.

## 0.5.0 — 2026-09-15 — verifiable by third parties, reviewed by five models

Council of five models (Claude Fable 5.1, Opus 4.8, Sonnet 5, Haiku 4.5, Gemini 3.1 Pro) on the v0.4.1 code in
three parts; real findings fixed, each with a test:
- **Evidence:** signed audit ledger under a process lock (`fcntl`) like the mission ledger; a torn last line now
  refuses the append instead of silently forking back to GENESIS; the signed key set is exact (an enriched line
  fails); every line's digest is recomputed in the chain check; `GENESIS` accepted once; the key registry is
  read-only during verification; `record_digests_bound` defaults to fail-closed; signed records carry `alg` and
  **no floats** (`latenza_dichiarata_ms` integer); the verbale's latency is **measured** from the crew-signed
  emission to the ED-signed receipt, the receiver's declaration is reported separately; a naive `ts_emissione`
  is refused. Mission case file: free text never at rest (fingerprint only), over-length notes refused rather
  than truncated, FSM state re-read under the lock (compare-and-append). Pre-alert anchors written under a lock.
- **Board/server:** expiry now clears confirmations, START tags and patient type; confirmations capped and
  re-checked under the lock before signing; `/rimuovi-nota` bound-check and removal under one lock with the
  audit before the effect; `/stato_ps` audit and state under one lock; `?marca=1` parsed, not substring-matched;
  atomic token rotation; bodies read under an absolute deadline; `/prealert` accepts `eta_mesi`; monotonic
  pre-alert ids and pruning of long-expired records; positions, messages, notes and alternative destinations
  are **salted commitments** (HMAC with a random salt kept in memory), not bare digests of enumerable values.
- **Clinical:** `prealert()` validates vitals and refuses age < 16 even when called directly; `bpco_scala2` must be
  a boolean; absent pulse is an arrest; adult JRCALC sepsis markers are not applied to children; no GCS but not
  alert → conservative criterion; `messaggio_prealert` and the sepsis function validate their inputs; metrics
  take an injectable clock and their over/under-triage proxies are stated as not a clinical error measure.
- **Third-party verification:** `health_verify.py` (reference) and independent verifiers in JavaScript, Go and Rust
  (`verifiers/`), all keeping number lexemes and honouring the two canonical profiles (`FORMAT.md`); differential
  oracle on 16 sandboxed fixtures (intact, tampered, re-signed, deleted, re-ordered, NaN, duplicate keys, edited
  verbale, claims without registry): 0 divergences; required in CI.
- **Texts:** "tamper-evident" instead of "incorruptible"; the declared band modification named as such; MDR Rule 11
  exposure and what the signatures do and do not prove stated in the honest scope.


## 2026-09-13 — v0.4.1, packaging fix

The 0.4.0 wheel published minutes earlier did not contain `prealert_criteria`, `verbale_probatorio`,
`coordinamento` (nor `news2_certificate`): `pyproject.toml` lists modules by hand and the list had not been
updated. Found by installing from the public index into a clean venv. Fixed, and `test_packaging.py` now fails
whenever a product module is not in the list. The 0.4.0 release is kept for the record and marked superseded;
the index serves 0.4.1.

## 2026-09-13 (second step) — what the field leaders do, done the OMEGA way (v0.4.0)

Order of the author: «check the competitors and add what is missing». Compared online (Pulsara,
Twiage/TigerConnect EMS, corpuls.mission LIVE, NIDA; pages read the same day) and added, each with the
house rule — closed values or digests in the signed ledger, free text and bytes only in memory with the
board TTL, nothing clinical on disk:

- **`coordinamento.py`** — patient type → team to alert (derived from the computed pathways and the 2025
  conditions, closed vocabulary shared with the ED receipt); en-route ETA/position (`POST /posizione`,
  exact in memory, ~1 km in the ledger); two-way crew↔ED messages (`POST /messaggio`, `GET /messaggi/<id>`);
  ECG / scene photo / document attachments (`POST /allegato/<id>` raw bytes with magic-byte and size checks,
  `GET /allegato/<id>/<n>`, expire with the board); "close the loop" clinical outcome (`POST /esito`);
  QA/QI metrics (`GET /metriche`: volumes, receipt latency, alternative-response rate, outcome mix,
  over/under-triage proxies against the 2025 criteria); major incidents with several patients
  (`POST /incidente`, `GET /incidente/<id>`, `GET /incidenti`, `incidente_id` on `/valuta`).
- Deliberately **not** added: audio/video calls and live telemetry (infrastructure, not evidence),
  patient identity lookup (PII-free by design), NEMSIS export (Europe = FHIR).
- **Review by three independent models (same day), verified on the code and fixed:** the incident
  description (free text: place, plates, names) went to the ledger in clear — now by digest; attachments
  were served inline in the board's origin (an XHTML uploaded as `text/xml` could run script in the ED
  browser) — now download-only with `nosniff` and `CSP: sandbox`; check-then-append races with the board
  expiry — now re-checked under the lock (410 if expired meanwhile), expired records stay empty, incidents
  expire at 2×TTL; an ETA update mutated the already-anchored pre-alert — now `eta_corrente` on the record,
  the anchored object is immutable; over/under-triage counted every outcome — now once per pre-alert on the
  last one; negative `Content-Length` refused. Two claims were checked and found false (GET endpoints
  without token; truncated code). Added what the reviewers named as still missing and in scope: **ED
  status / divert** (`POST /stato_ps`: accetta | saturo | dirotta, alternative destination by digest,
  returned with every `/valuta`), **escalation on missing receipt** (`da_escalare` in `/metriche` after 120 s),
  **START triage tags** per incident (`triage_start` on `/valuta`, counted in `/incidente/<id>`).
- **Second review round, verified and fixed:** incident ids were `len(list)+1` after expiry removal (collision,
  patients of two incidents mixed) — now a monotonic counter; expiry left `esiti` and `ricezioni` in RAM — now
  cleared; the ledger signature happened *before* the under-lock expiry re-check (trail could hold an event the
  board discarded) — now check, sign and append happen under the same lock (`_evento_su_record`); `/ricezione`
  accepted an expired record — now 404 and capped; START tags were not signed nor updatable — now `POST /triage`
  (signed, re-triage allowed) and the initial tag on `/valuta` is signed too; no per-record caps (RAM exhaustion
  with a valid token) — now 10 attachments, 200 messages, 20 outcomes, 20 receipts, 500 incidents (429);
  the ~1 km position went to disk — now only the ETA and a digest of the position; `INCIDENTI` read outside the
  lock; a 30 s socket timeout on the handler against a declared-but-never-sent body. One claim checked and
  found false (the `arresto` key). Named as still missing and left out on purpose: push notifications
  (infrastructure), manual specialist invitation and per-message read receipts (candidates for a next step).
- Tests: `test_coordinamento.py` (bench-of-the-bench + one end-to-end flow over HTTP covering every endpoint,
  negatives first, ledger checked for absence of free text, bytes and coordinates, download headers, caps,
  monotonic incident ids, expiry with no repopulation, negative Content-Length). 125 in total. Honesty note:
  one transient red of `test_health.py` in 43 sequential runs (run 4 of 10), not reproduced in the following
  32 runs and with no captured output; cause not identified.

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
- **Third round (Fable + Gemini; Opus out of quota):** a row *without* `prev_sha256` after the start of the chain could impersonate a deleted row by carrying its digest — now legacy rows are accepted only at the head of the ledger, anything else is a break; a missing `HEALTH_TSA_CAFILE` is a named configuration error (`verified` False), not "TSA not trusted"; operator identity model (light enrollment by normalised name) written into the module docstring; a claimed `ensure_ascii` mismatch was checked and is not one (both sides canonicalise identically; test with an accented operator name added).
- **Tests**: 49 new (boundaries of every threshold, every paediatric band, hostile types, sepsis needs
  infection history, receipt vocabulary, tamper / re-sign with foreign key / row deletion detection,
  legacy-key and legacy-row boundaries, fabricated timestamp reply refused, persisted verbale,
  end-to-end over HTTP, bench-of-the-bench with a deliberately broken threshold) + 2 opt-in network
  tests with a real TSA (green against freetsa.org with its root CA on 2026-09-13; tampered token and
  wrong CA refused). 121 in total, in CI with and without `cryptography`; 10 consecutive full runs green
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
