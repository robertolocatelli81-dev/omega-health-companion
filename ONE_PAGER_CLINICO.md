# OMEGA Ambulanza Intelligente — pilota clinico (one-pager)

**Cosa:** un motore che, durante il trasporto in ambulanza, da vitali + farmaci +
segni clinici calcola gli score di emergenza **validati** e genera **un pre-alert
strutturato** per l'ospedale — così il pronto soccorso prepara la squadra giusta
*prima* dell'arrivo. Con provenienza incorruttibile (hash-chained).

## Cosa fa (misurabile, ROBUSTO)
- **6 percorsi tempo-dipendenti, score standard:** NEWS2 (RCP 2017), BE-FAST (ictus),
  qSOFA (Sepsis-3), trauma (ATLS/CDC), ACR (ERC), STEMI/cardio (ESC).
- **Pre-alert unico** con priorità + percorsi da attivare (stroke team, sepsi,
  trauma, ACR, emodinamica) + farmaci in uso + **interazioni gravi** note.
- **Provenienza OMEGA:** ogni pre-alert incatenato SHA-256 append-only →
  auditabile, non-ripudiabile («a che ora, con quali dati, non alterabile»).
- **Privacy by design:** dati effimeri; trasmissione solo all'ospedale di
  destinazione (flusso di cura); nessuna persistenza fuori dal ledger di audit.

## Cosa NON è (confine, honest-scope)
- **NON un dispositivo medico certificato.** Il pilota gira in **affiancamento**:
  il sistema calcola e propone, il personale 118 **decide e conferma**. Non
  diagnostica, non prescrive, non sostituisce il medico — attiva un *percorso*.
- Gli score sono standard *riconosciuti*, non algoritmi inventati.

## Il beneficio clinico (ESTRAPOLATO — da MISURARE nel pilota)
La letteratura mostra che il pre-alert ospedaliero riduce i tempi door-to-treatment
in ictus/STEMI. Il **nostro** beneficio nel vostro contesto è precisamente ciò che
il pilota misura — non lo dichiariamo provato. Endpoint proposti: minuti risparmiati
door-to-treatment, appropriatezza delle allerte (sensibilità/falsi allarmi), tempo
di handover.

## Posizionamento vs competitor (onesto)
- **Pulsara** (leader): evidenza clinica pubblicata (BMJ Open Quality 2022, Bladin et al., Ambulance Victoria/Monash: STEMI −23 min,
  door-to-CT −44 min), adozione reale, app di comunicazione team. **È avanti a noi.**
- **ESO / ImageTrend:** integrazione dati EMS↔EHR↔registri; predizioni.
- **Dove OMEGA si distingue (da validare):** (1) **provenienza hash-chained** del
  pre-alert — *nessuno dei competitor esaminati in COMPETITOR_ROADMAP.md lo documenta*: evidenza medico-legale e di audit
  incorruttibile; (2) **multi-percorso in un unico alert** (non solo stroke/STEMI);
  (3) **open / self-hosted, no black-box, no lock-in**.
- **Onestà:** loro hanno evidenza + adozione + integrazione; noi un prototipo con
  un angolo distintivo. Il pilota serve a colmare il gap che ci separa.

## Cosa serve dal vostro reparto/118
Un referente clinico, dati de-identificati di un campione retrospettivo (per la
taratura/misura), e una call di 30 minuti. In cambio: l'evidence pack riproducibile
+ il vantaggio della provenienza auditabile sui vostri percorsi tempo-critici.

*Contatto: Roberto Locatelli · roberto.locatelli.81@gmail.com · github.com/robertolocatelli81-dev. Codice open, verificabile.*
