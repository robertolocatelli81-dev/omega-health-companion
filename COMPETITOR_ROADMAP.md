# Competitor comparison & roadmap — what to match, what to add, where to improve (2026-08-08)

Ricerca vera sui competitor prehospital. Onesto: loro sono avanti (evidenza,
adozione, integrazione); noi abbiamo un angolo distintivo (provenienza). Questo
è cosa PRENDERE (feature standard che ci mancano) e dove SUPERARLI.

## I competitor reali
| Player | Forza | Prova / scala |
|---|---|---|
| **Pulsara** | pre-alert stroke/STEMI + app comunicazione team | **evidenza pubblicata** (BMJ Open Quality 2022, Bladin et al., Ambulance Victoria/Monash — PubMed 35851025: STEMI −23 min, door-to-CT −44 min); adozione reale |
| **ESO Prehospital Intelligence** | dati EMS↔ospedale, predizioni (ha acquisito d2i) | piattaforma, molti clienti |
| **ImageTrend** | integrazione bidirezionale EMS↔EHR↔registri statali | connettività, outcome data |
| **RapidSOS UNITE** | intelligence per centrali 911, integrazione CAD | scala pubblica safety |
| **TraumaSoft / Prehos** | all-in-one (dispatch, ePCR, billing) + alert STEMI/stroke | ~200 clienti (TraumaSoft) |

## COPIARE (feature standard che ci mancano — priorità)
1. **Evidenza clinica pubblicata** — Pulsara vince con questa. Il pilota deve
   MISURARE i tempi (endpoint pre-registrati) e produrre un paper. È il gap #1.
2. **App di comunicazione team** — Pulsara collega ambulanza↔PS↔specialisti in
   tempo reale. Noi abbiamo il motore; serve il canale/interfaccia.
3. **Integrazione EHR/registri** (ImageTrend/ESO) — bidirezionale, outcome data
   di ritorno all'EMS. Senza, restiamo un'isola.
4. **ECG → STEMI automatico** (visto in ESO/Prehos) — noi oggi usiamo il flag ECG
   manuale; aggiungere la lettura automatica del tracciato.

## Da aggiungere / migliorare (il nostro angolo)
1. **Provenienza hash-chained del pre-alert** — nessuno dei competitor esaminati qui lo documenta. Evidenza
   medico-legale incorruttibile (dispute, audit, qualità, responsabilità). È il
   differenziatore OMEGA nato dal core regtech. → renderlo il messaggio #1.
2. **Multi-percorso in un unico alert** — Pulsara è forte su stroke/STEMI; noi
   copriamo anche sepsi, trauma, ACR nello stesso pre-alert. Ampliare a percorsi
   pediatrici/ostetrici.
3. **Open / self-hosted / honest-scope** — no black-box, no lock-in, verificabile.
   Per SSN pubblici e privacy-sensitive è un vantaggio; per grant open lo è di più.

## FATTO 2026-09-06 (dalla comparazione al codice)
Il gap #3 (integrazione EHR) ha ora il primo pezzo REALE: `fhir_export.py` —
pre-alert → **Bundle FHIR R4** (vitali con LOINC ufficiali, RiskAssessment,
Flag per gli avvisi, **Provenance col hash del ledger** = il differenziatore
OMEGA dentro lo standard, non accanto), **validato con 0 errori contro il
validatore HAPI FHIR pubblico** (prima passata: 47 errori fullUrl/reference,
corretti — l'oracolo esterno ha battuto il banco interno). Perché FHIR è il
futuro DATATO: **EHDS in vigore dal 26/03/2025, scambio primario in applicazione
da marzo 2029** (fonte UE verificata). In più: **handover ATMIST** (formato di
consegna standard che i PS conoscono — Pulsara-parity sulla struttura) e
**allegato ECG con SHA-256** (il tracciato viaggia col pre-alert verificabile,
LIFENET-style, SENZA interpretazione automatica — onesto). Il gap #4 (lettura
ECG automatica) resta APERTO deliberatamente: senza validazione clinica sarebbe
un overclaim. Stesso giorno: 10 difetti clinici fixati dall'attacco 4-menti
(arresto respiratorio, gate pediatrico, validazione vitali, privacy ledger
digest-only, PDE5/nitrati, trauma anticoagulato, BE-FAST, scala 2 BPCO).

## Realismo
Non «battiamo Pulsara» oggi: loro hanno evidenza + adozione, noi un prototipo.
Ma l'angolo provenienza + multi-percorso + open è reale e non presidiato. Il
cammino: pilota che misura → evidenza → integrazione → adozione. Un passo per volta.
