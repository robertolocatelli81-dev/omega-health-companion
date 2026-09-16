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

- Our two documents: 0 errors on both validators. Warnings, all explained: `ch-ems-epr-*` constraints (the patient is
  anonymous by design before identification), our own code system unknown to the terminology server, the IVR identifier
  type `MN` against the HL7 identifier-type value set.
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
