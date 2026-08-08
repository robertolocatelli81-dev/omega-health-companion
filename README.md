# OMEGA Health Companion

Assistente sanitario INFORMATIVO (non diagnostico, non prescrittivo). Tre moduli + orchestratore ambulanza.

- `companion_seed.py` — verifica disinformazione sanitaria vs fonti ufficiali
- `interazioni_farmaci.py` — interazioni farmacologiche gravi note (rimando farmacista)
- `barella_prealert.py` — NEWS2 (score validato RCP 2017) + pre-alert ospedale
- `ambulanza_intelligente.py` — i tre in un flusso: pre-alert integrato (gravita + farmaci + interazioni)

Confine: aggrega/comunica standard clinici validati, NON diagnostica ne prescrive; il medico decide. Privacy: dati effimeri, nulla persiste, trasmissione solo allospedale. Ogni modulo ha un banco che SA FALLIRE (controllo positivo + null).
