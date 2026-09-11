#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — AMBULANZA INTELLIGENTE: i tre moduli in un solo flusso di emergenza.

Durante il trasporto, da un unico input (vitali + farmaci del paziente + età +
ETA all'ospedale) produce UN pre-alert integrato per il pronto soccorso:
  • NEWS2 + priorità        (barella_prealert)  — quanto è critico, ora
  • interazioni farmaci     (interazioni_farmaci) — cosa prende e quali rischi
  • verifica informazioni   (companion_seed)     — disponibile per dubbi del cittadino
così l'ospedale sa PRIMA dell'arrivo: gravità, terapie in corso, rischi.

CONFINE: aggrega e comunica standard clinici validati (NEWS2, interazioni note).
NON diagnostica, NON decide la terapia: il medico decide, ma arriva preparato.
PRIVACY: dati sanitari effimeri; trasmessi solo all'ospedale di destinazione.
"""
from __future__ import annotations
import os, sys
from typing import Dict, List, Optional
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import barella_prealert as B
import interazioni_farmaci as F
import companion_seed as C
import scores_emergenza as S
from datetime import datetime, timezone


def valuta_paziente(vitali: Dict, farmaci: List[str], eta: Optional[int],
                    eta_arrivo_min: int, fast_segni: Optional[Dict] = None,
                    clinica: Optional[Dict] = None, ancora: bool = False) -> Dict:
    """Il flusso completo dell'ambulanza intelligente → pre-alert integrato.
    fast_segni: {'face','arm','speech'}.
    clinica (tutte opzionali): {'gcs', 'meccanismo_maggiore', 'lesione_penetrante',
    'contesto_trauma', 'assenza_respiro', 'assenza_polso', 'dolore_toracico',
    'ecg_stemi'}. meccanismo_maggiore e lesione_penetrante attivano da soli il
    contesto traumatico (CDC field triage Step 2-3) — vedi scores_emergenza.trauma."""
    cl = clinica or {}
    # ── GATE PEDIATRICO (FIX 2026-09-06, 4-menti): NEWS2/qSOFA/CDC-adulti NON
    # sono validati sotto i 16 anni — un bambino con FC/FR fisiologiche usciva
    # "critico" e un lattante grave poteva uscire "basso". FAIL-CLOSED, non
    # punteggio sbagliato: serve PEWS/strumento pediatrico, qui dichiarato.
    # Validazione dei PARAMETRI non-vitali (FIX 2026-09-11): età e farmaci arrivano dalla rete.
    # eta="4" faceva TypeError (messaggio Python esposto al client); eta=-3 finiva nel percorso
    # pediatrico; eta assente saltava il gate pediatrico (fail-OPEN); farmaci=[{...}] crashava il
    # handler HTTP (AttributeError su .strip). Ogni caso è un problema NOMINATO, mai un'eccezione.
    if not isinstance(farmaci, list) or not all(isinstance(f, str) for f in farmaci):
        raise ValueError("farmaci deve essere una lista di stringhe")
    if len(farmaci) > 100 or any(len(f) > 120 for f in farmaci):
        raise ValueError("farmaci: lista troppo lunga o voce troppo lunga")
    # ── VALIDAZIONE VITALI (FIX 2026-09-06, 4-menti): dati impossibili/mancanti
    # → prima crashava (TypeError) o produceva NEWS2=11 plausibile da spazzatura.
    problemi = B.valida_vitali(vitali)
    # ETÀ (FIX 2026-09-11): mancante → il gate pediatrico saltava (fail-OPEN, score adulto);
    # "4" stringa → TypeError esposto al client; -3 → percorso pediatrico. Stesso rifiuto
    # strutturato dei vitali, problema nominato, mai uno score adulto su un'età sconosciuta.
    if eta is None:
        problemi.append("eta mancante: senza età il gate pediatrico non può decidere")
    elif isinstance(eta, bool) or not isinstance(eta, (int, float)) or eta != eta or not (0 <= eta <= 130):
        problemi.append(f"eta non valida: {eta!r} (atteso numero fra 0 e 130)")
    if problemi:
        return {"PRE_ALERT_INTEGRATO": {
                    "priorita": "NON_VALUTABILE_DATI_INVALIDI",
                    "eta_paziente": eta, "eta_arrivo_stimato_min": eta_arrivo_min,
                    "problemi_dati": problemi,
                    "azione_raccomandata": ("DATI VITALI INVALIDI O INCOMPLETI (sensore/unità?): "
                                            "verificare e rimisurare; comunicazione vocale diretta "
                                            "col PS — mai uno score da dati non plausibili"),
                    "percorsi_attivare": []},
                "confine": "fail-closed sui dati: uno score da input impossibili è un falso alert",
                "privacy": "dati effimeri, trasmessi solo all'ospedale di destinazione"}
    if eta < 16:
        return {"PRE_ALERT_INTEGRATO": {
                    "priorita": "NON_VALUTABILE_PEDIATRICO",
                    "eta_paziente": eta, "eta_arrivo_stimato_min": eta_arrivo_min,
                    "azione_raccomandata": ("PAZIENTE PEDIATRICO: NEWS2/qSOFA/criteri trauma "
                                            "adulti NON validati — usare PEWS/percorso pediatrico, "
                                            "comunicazione diretta col medico"),
                    "percorsi_attivare": ["PERCORSO PEDIATRICO: valutazione clinica diretta"]},
                "confine": "score adulti non applicabili in pediatria: rifiuto dichiarato, non un numero sbagliato",
                "privacy": "dati effimeri, trasmessi solo all'ospedale di destinazione"}
    pa = B.prealert(eta, vitali, eta_arrivo_min)
    inter = F.controlla(farmaci) if farmaci else {"interazioni_note_trovate": [],
                                                  "nessun_allarme": True}
    # tutti i percorsi tempo-dipendenti validati (attivano squadre dedicate)
    qs = S.qsofa(vitali["rr"], not vitali["alert_coscienza"], vitali["sbp"])
    fs = S.fast(fast_segni.get("face", False), fast_segni.get("arm", False),
                fast_segni.get("speech", False)) if fast_segni else None
    tr = S.trauma(cl.get("gcs", 15), vitali["sbp"], vitali["rr"],
                  cl.get("meccanismo_maggiore", False), cl.get("contesto_trauma", False),
                  cl.get("lesione_penetrante", False))
    # ERC: coscienza assente + respiro assente = arresto (polso inaffidabile)
    ar = S.acr(cl.get("assenza_respiro", False), cl.get("assenza_polso", False),
               coscienza_assente=not vitali["alert_coscienza"])
    ca = S.cardio(cl.get("dolore_toracico", False), cl.get("ecg_stemi", False))
    # ── avvisi farmacologici di percorso (FIX 2026-09-06, 4-menti): la lista
    # farmaci c'era già ma non parlava coi percorsi. Ora sì:
    classi_farmaci = set().union(*[F._classi(f) for f in farmaci]) if farmaci else set()
    avvisi = []
    if ca["sospetto"] and "inibitori-pde5" in classi_farmaci:
        avvisi.append("⛔ PDE5-inibitore in terapia: NON somministrare NITRATI (ipotensione grave)")
    anticoagulato = bool(classi_farmaci & {"warfarin", "doac"})
    percorsi = []
    if ar["arresto"]:               percorsi.append(ar["azione"])   # priorità assoluta
    if ar.get("arresto_respiratorio"): percorsi.append(ar["azione"])  # peri-arresto: vie aeree
    if fs and fs["sospetto_ictus"]: percorsi.append(fs["azione"])
    if ca["sospetto"]:              percorsi.append(ca["azione"])
    if tr["attiva_trauma_team"]:    percorsi.append(tr["azione"])
    # CDC field triage: trauma (anche apparentemente minore) in paziente
    # ANTICOAGULATO → rischio emorragia occulta/cerebrale, centro trauma
    contesto_trauma = tr["contesto_trauma"]
    if contesto_trauma and anticoagulato:
        avvisi.append("⚠️ TRAUMA in paziente ANTICOAGULATO (warfarin/DOAC): rischio emorragia "
                      "occulta/cerebrale anche con dinamica minore — centro con TC/neurochirurgia (CDC)")
        percorsi.append("TRAUMA ANTICOAGULATO: valutazione trauma center, TC precoce")
    # FIX 2026-08-08 (agente avversariale): qSOFA instrada a SEPSI solo FUORI da un
    # contesto traumatico. In un trauma, lo shock è emorragico fino a prova
    # contraria: mandare un emorragico a colture+antibiotici è il percorso SBAGLIATO
    # e ritarda sangue/chirurgia. Il trauma team ha la precedenza.
    if (qs["sospetto_sepsi"] and not tr["attiva_trauma_team"]
            and not ar["arresto"] and not ar.get("arresto_respiratorio")):
        # in arresto (anche respiratorio) il percorso è RCP/vie aeree, non colture
        percorsi.append(qs["azione"])
    # FIX 2026-08-08 (bug trovato in demo): un percorso tempo-critico attivo
    # eleva la PRIORITÀ anche se NEWS2 è basso (es. ictus con vitali normali).
    priorita = pa["PRE_ALERT_OSPEDALE"]["priorita"]
    azione_racc = pa["PRE_ALERT_OSPEDALE"]["azione_raccomandata"]
    if percorsi and priorita != "ALTO":
        priorita = "ALTO"
        # FIX 2026-09-06 (4-menti, fattori umani): prima la priorità saliva ad
        # ALTO ma l'azione restava «monitoraggio ordinario» dal NEWS2 basso —
        # messaggio CONTRADDITTORIO al PS. L'azione segue la priorità elevata.
        azione_racc = ("EMERGENZA: percorso tempo-critico attivo nonostante NEWS2 basso — "
                       "vedi percorsi_attivare")
    prealert_integrato = {
        **pa["PRE_ALERT_OSPEDALE"], "priorita": priorita,
        "azione_raccomandata": azione_racc,
        "farmaci_in_uso": farmaci,
        "interazioni_note": inter["interazioni_note_trovate"],
        "flag_farmacologico": not inter.get("nessun_allarme", True),
        "avvisi": avvisi,
        "qSOFA": qs["punti"], "BE_FAST": (fs["segni_positivi"] if fs else None),
        "trauma_team": tr["attiva_trauma_team"], "arresto": ar["arresto"],
        "arresto_respiratorio": ar.get("arresto_respiratorio", False),
        "cardio": ca["sospetto"],
        "percorsi_attivare": percorsi,
    }
    out = {
        "PRE_ALERT_INTEGRATO": prealert_integrato,
        "dettaglio_score": pa["score"], "dettaglio_interazioni": inter,
        "dettaglio_qsofa": qs, "dettaglio_fast": fs,
        "confine": "NEWS2/FAST/qSOFA e interazioni sono standard validati, NON diagnosi; il medico decide",
        "privacy": "dati effimeri, trasmessi solo all'ospedale di destinazione",
    }
    if ancora:   # appoggio OMEGA: provenienza hash-chained non-ripudiabile
        ts = datetime.now(timezone.utc).isoformat()
        out["provenienza_omega"] = S.ancora_prealert(prealert_integrato, ts)
    return out


def verifica_informazione(domanda: str) -> Dict:
    """Componente companion: verifica una claim sanitaria (per il cittadino)."""
    return C.rispondi(domanda)


# ── banco che SA FALLIRE: integrazione dei tre ────────────────────────────────
def banco_controllo() -> Dict:
    critico = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
                   alert_coscienza=False, temp=39.4)
    stabile = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72,
                   alert_coscienza=True, temp=36.7)
    # paziente critico che prende warfarin+aspirina (interazione grave)
    r1 = valuta_paziente(critico, ["warfarin", "aspirina"], 67, 8)
    # paziente stabile senza interazioni
    r2 = valuta_paziente(stabile, ["paracetamolo"], 40, 15)
    b_score = B.banco_controllo()["banco_sa_fallire"]
    f_score = F.banco_controllo()["banco_sa_fallire"]
    integrazione_ok = (r1["PRE_ALERT_INTEGRATO"]["priorita"] == "ALTO"
                       and r1["PRE_ALERT_INTEGRATO"]["flag_farmacologico"] is True
                       and r2["PRE_ALERT_INTEGRATO"]["priorita"] == "BASSO"
                       and r2["PRE_ALERT_INTEGRATO"]["flag_farmacologico"] is False)
    # caso trauma (punto cieco dell'agente): politrauma OCCULTO (vitali compensati,
    # solo meccanismo) → team ON + priorità ALTO; ed EMORRAGICO da trauma → team ON
    # ma percorso SEPSI assente (non instradare un emorragico ad antibiotici).
    occulto = valuta_paziente(dict(rr=16, spo2=98, su_ossigeno=False, sbp=120, hr=88,
                                   alert_coscienza=True, temp=36.8), [], 25, 12,
                              clinica={"gcs": 15, "meccanismo_maggiore": True})
    emorr = valuta_paziente(dict(rr=32, spo2=92, su_ossigeno=False, sbp=70, hr=130,
                                 alert_coscienza=False, temp=36.5), [], 30, 10,
                            clinica={"gcs": 8, "meccanismo_maggiore": True})
    ep = emorr["PRE_ALERT_INTEGRATO"]
    trauma_ok = (occulto["PRE_ALERT_INTEGRATO"]["trauma_team"] is True
                 and occulto["PRE_ALERT_INTEGRATO"]["priorita"] == "ALTO"
                 and ep["trauma_team"] is True
                 and not any("SEPSI" in p for p in ep["percorsi_attivare"]))
    # ── casi 4-menti 2026-09-06 (ognuno era un difetto MISURATO prima del fix) ──
    stabile_v = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72,
                     alert_coscienza=True, temp=36.7)
    # (a) arresto respiratorio: respiro assente, polso presente → vie aeree, MAI sepsi
    resp = valuta_paziente(dict(rr=0, spo2=60, su_ossigeno=True, sbp=90, hr=45,
                                alert_coscienza=False, temp=35.5), [], 60, 5,
                           clinica={"assenza_respiro": True, "assenza_polso": False})
    rp = resp["PRE_ALERT_INTEGRATO"]
    resp_ok = (rp["arresto"] is True    # ERC: non-responsivo + no respiro = arresto
               and not any("SEPSI" in p for p in rp["percorsi_attivare"])
               and rp["priorita"] == "ALTO")
    # (b) pediatrico → rifiuto dichiarato, mai score adulto
    ped = valuta_paziente(stabile_v, [], 4, 10)["PRE_ALERT_INTEGRATO"]
    ped_ok = ped["priorita"] == "NON_VALUTABILE_PEDIATRICO" and "NEWS2" not in ped
    # (c) dati impossibili → rifiuto nominativo, mai NEWS2 da spazzatura
    inv = valuta_paziente(dict(rr=-5, spo2=150, su_ossigeno=False, sbp=999, hr=0,
                               alert_coscienza=True, temp=45), [], 30, 10)["PRE_ALERT_INTEGRATO"]
    inv_ok = inv["priorita"] == "NON_VALUTABILE_DATI_INVALIDI" and len(inv["problemi_dati"]) >= 3
    # (d) STEMI + sildenafil in terapia → avviso NO NITRATI
    pde5 = valuta_paziente(stabile_v, ["sildenafil"], 60, 10,
                           clinica={"dolore_toracico": True})["PRE_ALERT_INTEGRATO"]
    pde5_ok = any("NITRATI" in a for a in pde5["avvisi"])
    # (e) trauma minore in anticoagulato (DOAC) → avviso + percorso trauma-center
    antico = valuta_paziente(stabile_v, ["apixaban"], 78, 10,
                             clinica={"contesto_trauma": True})["PRE_ALERT_INTEGRATO"]
    antico_ok = (any("ANTICOAGULATO" in a for a in antico["avvisi"])
                 and antico["priorita"] == "ALTO")
    # (f) contraddizione risolta: ictus con vitali normali → ALTO e azione coerente
    ictus = valuta_paziente(stabile_v, [], 70, 10,
                            fast_segni={"face": True})["PRE_ALERT_INTEGRATO"]
    coeren_ok = ictus["priorita"] == "ALTO" and "monitoraggio" not in ictus["azione_raccomandata"]
    fix_4menti_ok = resp_ok and ped_ok and inv_ok and pde5_ok and antico_ok and coeren_ok
    return {
        "sotto-banco NEWS2 sa fallire": b_score,
        "sotto-banco interazioni sa fallire": f_score,
        "integrazione (critico+interazione->ALTO+flag; stabile->BASSO+no-flag)": integrazione_ok,
        "trauma (occulto->team+ALTO; emorragico->team e NO sepsi)": trauma_ok,
        "fix 4-menti (resp-arrest, pediatrico, dati-invalidi, PDE5, anticoag, coerenza)": {
            "arresto_respiratorio": resp_ok, "gate_pediatrico": ped_ok,
            "dati_invalidi": inv_ok, "pde5_no_nitrati": pde5_ok,
            "trauma_anticoagulato": antico_ok, "azione_coerente": coeren_ok},
        "banco_sa_fallire": (b_score and f_score and integrazione_ok and trauma_ok
                             and fix_4menti_ok),
    }


if __name__ == "__main__":
    import json
    print("═══ BANCO INTEGRATO (i tre moduli insieme) ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\n═══ AMBULANZA: paziente critico su warfarin+aspirina, arrivo 8 min ═══")
    vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
               alert_coscienza=False, temp=39.4)
    out = valuta_paziente(vit, ["warfarin", "aspirina", "ramipril"], 67, 8)
    print(json.dumps(out["PRE_ALERT_INTEGRATO"], ensure_ascii=False, indent=1))
