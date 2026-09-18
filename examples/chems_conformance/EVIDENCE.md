# CH EMS conformance evidence (measured 2026-09-16)

Everything the README and our messages say about CH EMS conformance is reproducible from the files in this folder.

## What was validated
- `omega-full` = `../chems_document_sample.json` (the full pre-alert), `omega-minimal` = `../chems_document_sample_minimal.json`
  (the earliest pre-alert: alarm time, one vital, patient not alert, no colour, no destination) — both produced by
  `python3 chems_validate.py --sample examples/chems_document_sample.json`.
- `ig-Bundle-1/1b/2/2b-Einsatzprotokoll.json` = the four example documents published by the IG, downloaded on 2026-09-16
  from `https://fhir.ch/ig/ch-ems/2.0.0-ballot/Bundle-<n>-Einsatzprotokoll.json` (byte-for-byte; semantically identical
  to the copies in the package `ch.fhir.ig.ch-ems#2.0.0-ballot`). They are HL7 Switzerland's, not ours, and are kept
  here only so the measurements below can be re-run.

## How
- Official validator: `java -jar validator_cli.jar <doc> -version 4.0.1 -ig ch.fhir.ig.ch-ems#2.0.0-ballot -profile
  http://fhir.ch/ig/ch-ems/StructureDefinition/ch-ems-document` (validator_cli 6.10.4; dependencies resolved by the
  validator: ch.fhir.ig.ch-core 7.0.0-ballot, ch.fhir.ig.ch-term 3.4.0; terminology tx.fhir.org). Wrapper: `chems_validate.py`.
- Matchbox (ahdis, public): `POST https://test.ahdis.ch/matchboxv3/fhir/$validate?profile=…/ch-ems-document|2.0.0-ballot`.
- Outputs: `<name>.validator_cli-6.10.4.OperationOutcome.json`, `<name>.matchbox.OperationOutcome.json`, `summary.json`.

## Result
| document | validator_cli errors | validator_cli warnings | Matchbox errors | Matchbox warnings | sha256 |
|---|---|---|---|---|---|
| omega-full | 0 | 8 | 0 | 7 | `912e7d252cb4e474…` |
| omega-minimal | 0 | 6 | 0 | 4 | `830ba6eaeb6d123e…` |
| ig-Bundle-1 | 2 | 74 | 0 | 31 | `c5f310137e75d3bc…` |
| ig-Bundle-1b | 2 | 80 | 0 | 35 | `6294ca3471eaac0a…` |
| ig-Bundle-2 | 2 | 57 | 0 | 29 | `26588be51d3c1cba…` |
| ig-Bundle-2b | 2 | 63 | 0 | 33 | `2b2c560a46c192e8…` |

- Our two documents: 0 errors on both validators. Warnings, all explained: `ch-ems-epr-*` constraints (the CH Core EPR
  profiles are not met: the patient is anonymous by design before identification, and the Composition carries no
  `identifier` and no `confidentiality`, which `ch-core-composition-epr` requires — measured on 2026-09-18, see below),
  our own code system unknown to the terminology server, the IVR identifier type `MN` against the HL7 identifier-type
  value set.
- The IG's four examples: 0 errors on Matchbox, 2 errors each on validator_cli 6.10.4 — `Composition.confidentiality`
  extension coding SNOMED 17621005 with display "Normal" is refused for language de-CH ("Normal (qualifier value)"), and
  that display error makes the Composition fail its profile, so the `Bundle.entry:Composition` slice is reported as not
  found. See the OperationOutcome files. Reported to the IG authors as ballot feedback material.

## 5× bench on real online data
`bench_real_online_5x.txt`: five runs, each re-downloading the four IG documents, running positive controls first (a
tampered document must be refused by the reader; a document without Composition must fail on Matchbox), then the reader
(`chems_ingest.py`) + scoring + signed anchor verified offline by `health_verify.py`, Matchbox and validator_cli on all six
documents. Results identical across the five runs.

## Reader on the IG examples
`python3 chems_ingest.py examples/chems_conformance/ig-Bundle-1-Einsatzprotokoll.json` extracts mission number, six
mission times, GCS, NACA and blood pressure; NEWS2 is not computed because the vital set is absent, and the output says
which inputs are missing (`test_chems_ingest.py::test_real_ig_examples_are_read`).

## Re-run on 2026-09-18 (`rerun_20260918/`)
Everything above was measured again from scratch on 2026-09-18 (validator_cli 6.10.4 jar re-downloaded, sha256
`1106b9d58f9e363e…`; the four IG examples re-downloaded, sha256 unchanged; our two documents unchanged). Same results:
our two documents 0 errors on both validators (8 and 6 warnings on validator_cli), the four IG examples 2 errors each on
validator_cli 6.10.4 and 0 on Matchbox. Log: `rerun_20260918/validator_cli_run.log`, counts: `rerun_20260918/summary.json`.

Two additional measurements, with positive controls:
- **Matchbox does not check display names.** `positive-control-display-banana.json` is our full document with
  `Coding.display = "Banana"` on LOINC 8867-4 (heart rate). validator_cli 6.10.4: 1 error ("Wrong Display Name 'Banana'
  for http://loinc.org#8867-4"). Matchbox (test.ahdis.ch/matchboxv3, ch-ems-document|2.0.0-ballot): 0 errors, no issue
  mentioning the display, identical counts to the unmodified document. So "0 errors on Matchbox" says nothing about
  display names; the 2 errors validator_cli reports on the IG examples are a check Matchbox does not run, not a
  disagreement. The broken-document control (`positive-control-no-composition.json`, no Composition) fails on both
  (Matchbox: 13 errors), so Matchbox was validating. Matchbox's own OperationOutcome states why: "powered by matchbox 4.1.16 … org.hl7.fhir.core
  6.10.4", validation parameters `displayIssuesAreWarnings=true`, `txServer=http://localhost:8080/matchboxv3/tx` (its
  internal terminology server), file `rerun_20260918/positive-control-display-banana.matchbox.OperationOutcome.json`.
- **The element shorts are not valid LOINC display names.** `omega-full-with-short-displays.json` is our full document
  with the shorts from the profiles copied into `Coding.display`: "Patient Status" on LOINC 77941-3
  (ch-ems-observation-statuspriority) and "Level of Responsiveness (AVPU)" on LOINC 11454-6 (ch-ems-observation-avpu).
  validator_cli 6.10.4 with tx.fhir.org: 2 errors ("Valid display is … 'Final patient acuity NEMSIS'" and
  "… 'Responsiveness assessment at First encounter'"). Matchbox: 0 errors (see previous point). Our exported documents
  omit `display` on these two codes.
- **Ablations (2026-09-18, `rerun_20260918/abl-*`).** `abl-Bundle-1-no-normal-display.json` is the IG's Bundle-1 with
  only the `display` removed from the SNOMED 17621005 coding in `Composition.confidentiality` (extension): validator_cli
  6.10.4 gives 0 errors (39 information, 72 warnings), so the `Bundle.entry:Composition` slice error is a consequence of
  that single display error. `abl-omega-minimal-requester-toplevel.json` is our minimal document with the requesting
  Organization moved from `ServiceRequest.contained` to a bundle entry: 1 error, "Reference is internal which isn't
  supported by the specified aggregation mode(s) for the reference (contained)" at `ServiceRequest.requester`. Matchbox gives the same error (plus the consequent `Bundle.entry:Composition` slice error), 2 errors in total.
  Note that the IG's own QA runs with `checkAggregation` off, so this is not visible in the published qa.html.
- **Why the IG's own QA shows 0 errors for the same examples.** The published `qa.html` for 2.0.0-ballot (IG Publisher
  v2.2.9, tx.fhir.org/r4) runs the validator with `displayWarnings` on, which reports display-name mismatches as
  information/warning instead of error; the examples carry `Composition.language = de-CH`, and for that language
  tx.fhir.org accepts only "Normal (qualifier value)" for SNOMED 17621005. With validator_cli's default settings the
  same mismatch is an error.
- **What the `ch-ems-epr-*` warnings are exactly (2026-09-18, `rerun_20260918/abl-omega-minimal-epr-profiles*`).** Our
  minimal document with `ch-core-composition-epr` declared on the Composition and `ch-core-patient-epr` on the Patient
  (`meta.profile`), validated as before: the EPR profiles fail on `Composition.identifier` (min 1), `Composition.confidentiality`
  (min 1), `Composition.subject` (must be a `ch-core-patient-epr`), and on the Patient on `identifier`, `name`, `gender`,
  `birthDate` and `ch-pat-1-epr` (family name). Nothing else. So "anonymous patient" explains the patient warning; the
  Composition warning is about the missing identifier and confidentiality (not required by CH EMS itself), and the document
  warning follows from the Composition one. (The other errors in that OperationOutcome are artefacts of declaring the EPR
  profiles: the CH EMS slices then no longer match; they are not findings.)

## Release 0.6.1 (2026-09-18, `release_0.6.1/`)
The two documents were regenerated with `Composition.identifier` (version-independent) and `Composition.confidentiality` = N
with the CH Core EPR confidentiality extension (SNOMED 17621005, no display); the identifier is seeded from the mission
number, the UTC-normalised alarm time and the per-patient `prealert_id` (never from the export instant). New sha256: omega-full `30f15d0e2ce24e19…`,
omega-minimal `9e9bb8185b31d625…`. validator_cli 6.10.4: 0 errors, 8 and 6 warnings (unchanged set); Matchbox: 0 errors,
7 and 4 warnings. `abl-omega-minimal-composition-epr.json` declares `ch-core-composition-epr` on the new Composition: the
only remaining EPR error is `Composition.subject` ("Unable to find a profile match … ch-core-patient-epr", the anonymous
patient), plus the consequent `Bundle.entry:Composition` slice error; no error mentions `identifier` or `confidentiality`
any more. So the `ch-ems-epr-composition` warning on our documents now has exactly one cause: the subject.
- **Two more ablations on the IG's Bundle-1 (2026-09-18, `rerun_20260918/abl-Bundle-1-*`).** With only `Composition.language`
  ("de-CH") removed: 0 errors (37 information, 74 warnings) — the display "Normal" is rejected in the de-CH language
  context, not per se. With the display replaced by "Normal (qualifier value)": 0 errors (40 information, 72 warnings).
  So both suggested fixes for the examples (omit the display, or use the display tx.fhir.org offers for de-CH) are measured.
- **Identifier-type warning, two more ablations (2026-09-18, `rerun_20260918/abl-mn-plus-*`).** Our minimal document with a
  second coding next to IVR#MN on `Encounter.identifier:missionNumber.type`: with v2-0203 `MR` the extensible-binding
  warning disappears (0 errors, 5 warnings); with v2-0203 `VN` the identifier matches the `VisitNumber` slice as well
  (discriminator `value:$this`): "Element matches more than one slice" and "Slice missionNumber not found", 7 errors.
