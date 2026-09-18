# Intended use / Zweckbestimmung — omega-health-companion

**Status: pilot software. Not a medical device. Not CE-marked, not Swissmedic-registered, no clinical evaluation.**
Author: Roberto Locatelli (individual developer), 2026. This document exists because the qualification of software
as a medical device is decided by the *intended use the manufacturer defines* (Swissmedic Merkblatt
BW630_30_007, v3.0, 21.04.2026, §4: «Massgeblich für die Qualifizierung ist also die vom Hersteller definierte
Zweckbestimmung»). It states what the software is for, what it is not for, and the two profiles it can run in.

## 1. Two run profiles (declared at start-up, `OMEGA_PROFILO`)

### `comunicazione` — communication and evidence only
The server receives the vital signs and mission data *as sent by the crew*, shows them to the emergency
department, records who sent what and when in a signed hash-chained ledger, and renders the pre-alert as a
CH EMS document. **It computes and shows no score, no priority, no recommendation, no pathway.** The fields that
would carry them are removed and listed in every response (`campi_non_calcolati`).

Why this profile exists: Swissmedic (same Merkblatt, §4) qualifies software as a medical device only «falls sich
die Verarbeitung der medizinischen Daten nicht auf die Speicherung, Archivierung, einfache Suche, Kommunikation
oder verlustfreie Kompression beschränkt». In this profile the processing *is* limited to storage, archiving,
communication and search of the data as entered. This is the same intended-use line a US vendor (Pulsara)
publishes for its platform. We state it as our reading of the Merkblatt, not as a Swissmedic decision: only a
qualification by the manufacturer under the ordinance, or an authority's ruling, settles it.

### `punteggi` — scores shown (default)
The server additionally computes NEWS2, qSOFA, BE-FAST, the RCEM/AACE 2025 pre-alert criteria, the paediatric
gate and the drug-interaction flags from the inputs, and shows them to the department with the inputs they came
from. Intended use: **information to organise the reception of a pre-announced patient; the clinical decision is
the clinician's.** This is *supporting information for a diagnostic or therapeutic decision about an individual*
and therefore, once placed on the market with that purpose, falls under **EU MDR Annex VIII Rule 11** and the
Swiss **Medizinprodukteverordnung (MepV, SR 812.213)**, which applies Rule 11 (Merkblatt §5.1: «Die Regel 11 des
Anhangs VIII EU-MDR … gilt sowohl für eigenständige als auch für in Medizinprodukten eingebettete
Medizinprodukte-Software»). Expected class: IIa (or higher, depending on the seriousness of the decisions the
information may lead to). **No conformity assessment has been done.** An EMS service or hospital that runs this
profile with real patients does so as a *pilot under its own clinical governance*, not on the basis of a
certification we do not have.

## 2. What the software is not for (both profiles)
- Not for diagnosis, not for treatment decisions, not for monitoring a patient, not a replacement of the
  radio/phone pre-alert call or of the clinician's assessment.
- Not an ePCR: it does not document the mission; it reads CH EMS documents produced by ePCRs and anchors their
  digest (see `chems_receipt.py`).
- Not identity-proofing: operator tokens tie an event to *who holds the token* (service-level identity). Legal
  non-repudiation towards third parties needs an eID/QTSP signature, which is not implemented and not promised.

## 3. Swiss context this build addresses (measured, not declared)
- **Format:** CH EMS 2.0.0-ballot (= eCH-0207 v2, IVR/HL7 Switzerland), 0 errors on the official validator and
  Matchbox for our documents; the four published examples are read end to end (`examples/chems_conformance/`).
- **Legal-binding archiving of the signed protocol:** eCH-0207 Beilage 1 (use cases) has the crew sign the final
  protocol, which is «rechtsverbindlich archiviert». The IG carries `Composition.attester` but profiles no
  byte-binding signature; our receipt (`chems_receipt.py`, `POST /chems/ingest`) anchors the exact bytes in an
  Ed25519-signed ledger with an optional RFC 3161 timestamp, verifiable offline by four independent verifiers.
- **Medication codes:** Swiss GTINs (GS1, `urn:oid:2.51.1.1`, as in the IG examples) are resolved to ATC codes
  with the official Swissmedic «Zugelassene Packungen» list (provenance and hash in `swissmedic_gtin_atc.py`);
  interactions are checked only on recognised drugs and the unrecognised ones are listed, never guessed.
- **Data protection (nDSG, SR 235.1, in force since 1.9.2023; health data = besonders schützenswerte
  Personendaten):** no health data at rest in the ledgers (digests only); the optional board journal is
  AES-256-GCM encrypted and never stores free text, attachments or coordinates; free text lives in process memory
  with a TTL. Transport encryption (TLS) and the secure-mail channel hospitals use in Switzerland (HIN, S/MIME) are
  the operator's infrastructure, not part of this software.
- **Languages:** documents and narratives in de / fr / it / en.

## 4. What would change the regulatory picture
A conformity assessment (MDR / MepV) for the `punteggi` profile; an IEC 62304 life-cycle file; a clinical
evaluation on pilot data. None of these exists today. Until then, the honest description is the one at the top
of this file.
