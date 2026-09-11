# OMEGA Health Companion — application template for a health grant call

**Stato onesto:** prototipo funzionante (non certificato, non validato clinicamente).
Il grant finanzia lo **studio pilota** che misura il beneficio e il percorso di
validazione — non un prodotto finito. Testo riutilizzabile per la call giusta (nessuna call è stata ancora scelta: dichiarato).

## ⚠️ Scadenze/call: da verificare su FONTI UFFICIALI (non aggregatori)
Gli aggregatori sono inaffidabili per le date (lezione OMEGA). Verificare la
finestra aperta direttamente su:
- **EU4Health / HaDEA:** https://hadea.ec.europa.eu/programmes/eu4health_en
- **EU funding for digital health:** https://health.ec.europa.eu/ehealth-digital-health-and-care/eu-funding-digital-health_en
- **HERA (emergenze sanitarie):** https://health.ec.europa.eu/health-emergency-preparedness-and-response-hera/funding-and-opportunities_en
- **EU Funding & Tenders Portal** (Horizon Europe Health cluster)
- **NLnet/NGI** (per il lato open-source): nlnet.nl/propose (riapre 3/9, deadline 3/11)
NB: EU4Health 2026 aveva una call chiusa il 6/1/2026 — cercare la prossima finestra.

## Progetto
**Titolo:** Open pre-hospital alerting con evidenza incorruttibile — ridurre il
door-to-treatment nei percorsi tempo-dipendenti.

**Abstract:** durante il trasporto in ambulanza, il sistema calcola score clinici
**validati** (NEWS2, FAST/ictus, qSOFA/sepsi, ATLS/trauma, ERC/ACR, ESC/STEMI) e
genera un pre-alert strutturato per l'ospedale, che prepara la squadra giusta
prima dell'arrivo. Distintivo: ogni alert è **hash-chained** (provenienza
auditabile, non-ripudiabile — nessuno dei competitor esaminati lo documenta) e il software è
**open / self-hosted** (no lock-in, ideale per SSN pubblici e privacy-sensitive).

## Cosa (ROBUSTO, già costruito e testato — aggiornato 2026-09-06)
6 percorsi validati, interazioni farmacologiche (multi-classe, avvisi di percorso:
⛔ nitrati/PDE5, ⚠️ trauma anticoagulato), pre-alert integrato con gate pediatrico
fail-closed e validazione vitali (unità °F/frazione rilevate), app team REALE
(server token-auth, calcolo lato server, bacheca PS, conferme) + CLI ambulanza,
**export FHIR R4 conforme ai profili vital-signs (0 errori strutturali su HAPI e sul validatore HL7)** + handover ATMIST + allegato ECG con
SHA-256, provenienza hash-chained **digest-only** (nessun dato sanitario nel
ledger). Suite: 71 test (unit + E2E su HTTP reale, banchi positivo/null, tipi ostili) eseguiti in CI a ogni push. Codice open,
riproducibile, ogni modulo con test che sa fallire (controllo positivo + null).

## Cosa NON è (confine, honest-scope)
NON dispositivo medico certificato; NON diagnostica; attiva **percorsi** validati,
il medico decide. Il pilota gira in affiancamento supervisionato.

## Cosa finanzia il grant (ESTRAPOLATO — il beneficio si misura qui)
- **Studio pilota** con un 118/DEA: endpoint pre-registrati (minuti door-to-treatment,
  sensibilità/falsi allarmi delle allerte, tempo di handover).
- **Validazione clinica** e percorso di certificazione (CE/MDR).
- Security review + integrazione EHR/CAD (gap vs competitor come Pulsara).

## Fit programmi
Digital health (EU4Health / Digital Europe), preparazione alle emergenze (HERA),
Horizon Health cluster, e — per il lato open-source — NGI/NLnet.

## Team & onestà
Solo-founder (Roberto Locatelli) + serve un **partner clinico** (referente 118/DEA)
per il pilota: i grant EU privilegiano i consorzi — l'aggancio a un ente sanitario
è il primo passo. Codice pubblico e verificabile su richiesta.

## Differenziatore vs stato dell'arte
Pulsara (leader) ha evidenza e adozione ma non ha la **provenienza incorruttibile**
né l'**open/self-hosted**. Il nostro angolo — evidenza auditabile + multi-percorso
+ open — è reale e non presidiato; il pilota lo valida.
