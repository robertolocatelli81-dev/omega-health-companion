# Intended use / Zweckbestimmung — omega-health-companion

**Status: pilot software. Not a medical device. Not CE-marked, not Swissmedic-registered, no clinical evaluation.**
Author: Roberto Locatelli (individual developer), 2026. This document exists because the qualification of software
as a medical device is decided by the *intended use the manufacturer defines* (Swissmedic Merkblatt
BW630_30_007, v3.0, 21.04.2026, §4: «Massgeblich für die Qualifizierung ist also die vom Hersteller definierte
Zweckbestimmung»). It states what the software is for, what it is not for, and the two profiles it can run in.

## 1. Two run profiles (declared at start-up, `OMEGA_PROFILO`; default `comunicazione` since 0.7.2)

### `comunicazione` — communication and evidence only (DEFAULT)
The server receives the vital signs, age, ETA and drug list *as sent by the crew*, shows them to the emergency
department (board page, `/api/board`, FHIR and ATMIST), and records who sent what and when in a signed hash-chained ledger;
the pre-alert can be rendered as a CH EMS document by the library (`fhir_chems.prealert_to_chems_document`, no server endpoint:
the mission data comes from the caller). The clinical inputs of the criteria engine (`clinica`, `fast_segni`, `condizioni`,
`sepsi`) are accepted but neither evaluated nor shown in this profile; the response names them in `campi_ignorati`.
**It computes and shows no score, no priority, no recommendation, no pathway.** The scoring
engine is not executed: the pre-alert is rebuilt from the validated inputs only, any decisional field sent by a
client (for example a score computed by the CLI) is ignored, and the fields that would carry them are listed in
every response as not computed (`campi_non_calcolati`). A record written by an earlier `punteggi` run and restored
from the board journal is served the same way: the live profile governs what is served, not the one active when the
record was written.

Why this profile exists: Swissmedic (same Merkblatt, §4) qualifies software as a medical device only «falls sich
die Verarbeitung der medizinischen Daten nicht auf die Speicherung, Archivierung, einfache Suche, Kommunikation
oder verlustfreie Kompression beschränkt». In this profile the processing *is* limited to storage, archiving,
communication and search of the data as entered. This is the same intended-use line a US vendor (Pulsara)
publishes for its platform. We state it as our reading of the Merkblatt, not as a Swissmedic decision: only a
qualification by the manufacturer under the ordinance, or an authority's ruling, settles it.

### `punteggi` — scores shown (opt-in: `OMEGA_PROFILO=punteggi`, written by the organisation that wants it)
The server additionally computes NEWS2, qSOFA, BE-FAST, the RCEM/AACE 2025 pre-alert criteria, the paediatric
gate and the drug-interaction flags from the inputs, and shows them to the department with the inputs they came
from. Intended use: **information to organise the reception of a pre-announced patient; the clinical decision is
the clinician's.** This is *supporting information for a diagnostic or therapeutic decision about an individual*
and therefore, once placed on the market with that purpose, falls under **EU MDR Annex VIII Rule 11** and the
Swiss **Medizinprodukteverordnung (MepV, SR 812.213)**, which applies Rule 11 (Merkblatt §5.1, verbatim: «Die Regel 11
des Anhangs VIII EU-MDR, die sowohl für eigenständige als auch für in Medizinprodukten eingebettete
Medizinprodukte-Software gilt, schränkt die Funktionalitäten für Software der Klasse I zwar stark ein, …»). Expected class: IIa (or higher, depending on the seriousness of the decisions the
information may lead to). **No conformity assessment has been done.** An EMS service or hospital that runs this
profile with real patients does so as a *pilot under its own clinical governance*, not on the basis of a
certification we do not have. That is why, since 0.7.2, this profile is never the default: activating an uncertified
decision-support function is an explicit act of the organisation (`OMEGA_PROFILO=punteggi`), recorded in its
configuration, never something a standard installation does on its own.

## 2. What the software is not for (both profiles)
- Not for diagnosis, not for treatment decisions, not for monitoring a patient, not a replacement of the
  radio/phone pre-alert call or of the clinician's assessment.
- Not an ePCR: it does not document the mission; it reads CH EMS documents produced by ePCRs and anchors their
  digest (see `chems_receipt.py`).
- Not identity-proofing: operator tokens tie an event to *who holds the token* (service-level identity). Legal
  non-repudiation towards third parties needs an eID/QTSP signature, which is not implemented and not promised.
  Roles (`equipaggio`, `centrale`, `ps`, `admin`) are recorded; in pilot mode (`OMEGA_REQUIRE_OPERATOR=1`) the
  emergency-department acts (`/ricezione`, `/stato_ps`, `/esito`) require the `ps` role (or the operator role
  `admin`, which carries no administrative rights: operators are managed only with the server token); other routes
  accept any authenticated operator. In pilot mode the board page carries no admin token; its confirmation form asks for the
  operator token, typed per request and never embedded in the page. Revoking an operator blocks the token; the per-operator signing key stays on disk and is
  reused if the same slug is re-issued, so pre- and post-revocation signatures are told apart by the ledger's
  timestamps and the registry's `storia` (events `riemissione_token` / `riattivazione_operatore` with `revocato_il`),
  not by the key. If the signing key itself may have been exposed, do not re-issue: revoke and create a new slug.
- The administration token IS the pre-existing server token (`team_token.txt`), i.e. the credential every terminal
  of a 0.6.x deployment already holds. Whoever has it can create operators, so `identita: autenticata` is proof
  against the body of a request, not against an insider who holds the server token. A pilot that wants the
  distinction must hand the server token to the administrator only and give every terminal an operator token
  (`OMEGA_REQUIRE_OPERATOR=1`). Procedure: `POST /operatori {"slug": "<name>", "ruolo": "equipaggio|centrale|ps|admin"}`
  with the server token (the operator token is returned once); a wrong role is fixed with `POST /operatori/revoca` and
  a new `POST /operatori {..., "riemetti": true}` with the right role.
- Without an operator token (default mode) the shared server token plus a declared name is still accepted, exactly
  as in 0.6.x; the response says `identita: dichiarata`, and a declared name that matches a registered operator is
  refused. Impersonation between *unregistered* names with the shared token is not prevented in default mode: that
  is what pilot mode is for.

## 3. Swiss context this build addresses (measured, not declared)
- **Format:** CH EMS 2.0.0-ballot (= eCH-0207 v2, IVR/HL7 Switzerland), 0 errors on the official validator and
  Matchbox for our documents; the four published examples are read end to end (`examples/chems_conformance/`).
- **Legal-binding archiving of the signed protocol:** eCH-0207 Beilage 1 (use cases) has the crew sign the final
  protocol, which is «rechtsverbindlich archiviert». The IG carries `Composition.attester` but profiles no
  byte-binding signature; our receipt (`chems_receipt.py`, `POST /chems/ingest`) anchors the exact bytes in the
  Ed25519-signed, hash-chained local ledger, together with whether the operator was authenticated (operator token) or
  declared (`identita` in the signed record, echoed by the verification). The receipt is verified offline with `chems_receipt.verifica_ricevuta`
  (Python); the ledger row it points to is additionally checkable by the four independent ledger verifiers
  (Python, JavaScript, Go, Rust). No RFC 3161 timestamp is attached to receipts today (the timestamp exists for the
  pre-alert verbale only).
- **Medication codes:** Swiss GTINs (GS1, `urn:oid:2.51.1.1`, as in the IG examples) are resolved to ATC codes
  with the official Swissmedic «Zugelassene Packungen» list (provenance and hash in `swissmedic_gtin_atc.py`);
  interactions are checked only on recognised drugs and the unrecognised ones are listed, never guessed.
- **Data protection (nDSG, SR 235.1, in force since 1.9.2023; health data = besonders schützenswerte
  Personendaten):** in the ledgers no free text and no vitals at rest — digests plus closed-vocabulary codes (triage
  colour, outcome code, ED state, receipt codes) and two declared exceptions: the administrative reason typed when a
  note is removed (in clear, must not contain patient data — PRIVACY.md) and the sanitised mission identifier of an
  ingested CH EMS document (an operational quasi-identifier towards the ePCR, never a person); the optional board journal is
  AES-256-GCM encrypted and never stores free text (messages, confirmation notes, incident descriptions, the
  free-text alternative destination), attachments or coordinates; free text lives in process memory with a TTL.
  Threat model of the journal: with the default key location (next to the file) it protects only a copy of the
  journal file alone; media theft or disposal takes the key along. To cover those, put the key on another medium
  (`OMEGA_BOARD_STORE_KEY`). A compromised host is never covered. Modified bytes are detected
  (AEAD); deletion or rollback of a whole entry is not — the signed ledger, not the journal, is the evidence.
  The journal is written synchronously inside the board lock: on a slow disk every clinical write waits for it.
- **One process:** the server is the standard-library `ThreadingHTTPServer`; locks are thread locks and the
  registry/journal files are per process. Do not run several worker processes on the same files. Transport encryption (TLS) and the secure-mail channel hospitals use in Switzerland (HIN, S/MIME) are
  the operator's infrastructure, not part of this software.
- **Languages:** documents and narratives in de / fr / it / en.

## 4. What would change the regulatory picture
A conformity assessment (MDR / MepV) for the `punteggi` profile; an IEC 62304 life-cycle file; a clinical
evaluation on pilot data. None of these exists today. Until then, the honest description is the one at the top
of this file.
