# OMEGA Health Companion

Assistente sanitario INFORMATIVO (non diagnostico, non prescrittivo). Tre moduli + orchestratore ambulanza.

- `companion_seed.py` — verifica disinformazione sanitaria vs fonti ufficiali
- `interazioni_farmaci.py` — interazioni farmacologiche gravi note (rimando farmacista)
- `barella_prealert.py` — NEWS2 (score validato RCP 2017) + pre-alert ospedale
- `ambulanza_intelligente.py` — i tre in un flusso: pre-alert integrato (gravita + farmaci + interazioni)

Confine: aggrega/comunica standard clinici validati, NON diagnostica ne prescrive; il medico decide. Privacy: dati effimeri, nulla persiste, trasmissione solo allospedale. Ogni modulo ha un banco che SA FALLIRE (controllo positivo + null).

## App di comunicazione team (team_comms.py)

Web-app self-hosted (stdlib): ambulanza pubblica il pre-alert, la bacheca del PS lo
vede in tempo reale (auto-refresh), il team conferma i percorsi. Provenienza
hash-chained. Avvio: `python3 -m team_comms 8097` -> http://127.0.0.1:8097/
Onesto: dimostrativa; in produzione TLS + auth personale + notifiche push + CAD/EHR.
