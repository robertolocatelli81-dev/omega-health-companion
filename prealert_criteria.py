#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prealert_criteria — criteri di pre-alert RCEM/AACE 2025 e messaggio «headline + ETA prima».

Fonte NORMATIVA (dato, non opinione): «UK NHS Ambulance Services & Emergency Department pre-alert
guideline», Royal College of Emergency Medicine + Association of Ambulance Chief Executives,
release luglio 2025, revisione luglio 2027 (PDF V2, dicembre 2025). Le soglie qui sotto sono
TRASCRITTE dal documento (pagina «Criteria for pre-alert calls to the ED»); l'impronta SHA-256
del PDF letto è in FONTE per la provenienza.

Cosa fa: da vitali + età + flag clinici dice SE la linea guida indica un pre-alert e PERCHÉ
(quale criterio, quale soglia), e compone il messaggio nell'ordine prescritto: headline concern
ed ETA prima («in case the call gets cut off»), poi ATMIST, in ≤ 60 secondi.

Cosa NON fa: non è uno score, non diagnostica, non decide la risposta dell'ospedale (la linea
guida stessa: «the decision to implement any such response is made at the discretion of the
senior clinical staff at the receiving hospital»). I criteri sono un DATO DI SOGLIA; il giudizio
clinico resta dell'equipaggio («significant concern in the view of the ambulance clinician»).

Onestà di scopo dichiarata nell'output (`non_valutato`): «downward-trending systolic where
symptomatic» richiede una SERIE di pressioni (qui non disponibile); «GCS <13 (new for patient)»
richiede di sapere il GCS abituale (qui non disponibile: un GCS <13 attiva il criterio in modo
conservativo e lo dichiara). Pediatria: qui ci sono i CRITERI DI PRE-ALERT per fasce d'età
(tabella adattata da PEWS nella linea guida), NON uno score pediatrico: il rifiuto di calcolare
NEWS2 sotto i 16 anni resta.

Tipi stretti come nel resto del companion (lezione 11/09): ogni flag è un booleano JSON, ogni
numero è un numero, ogni chiave ignota è un rifiuto NOMINATO, mai un'eccezione né un silenzio.
"""
from __future__ import annotations
from typing import Dict, List, Optional

FONTE = {
    "linea_guida": ("UK NHS Ambulance Services & Emergency Department pre-alert guideline "
                    "(RCEM / AACE)"),
    "release": "2025-07", "review": "2027-07", "versione_pdf": "FINAL-V2 (2025-12)",
    "url": "https://aace.org.uk/wp-content/uploads/2025/12/Pre-alert-guideline-RCEM-AACE-FINAL-V2.pdf",
    "sha256_pdf": "91da87b9e374e2cd4c1678177e36f5557cb1e5bfc643de70dd887b9787ac9038",
    "letto_il": "2026-09-13",
}

# ── 1. Fisiologia alterata nell'ADULTO («Adapted from NEWS2») — soglie trascritte ─────────────
# Respiratory rate ≤8 or ≥25 · O2 saturations on oxygen ≤91% (or ≤83% in chronic hypercapnic
# respiratory failure) · Systolic ≤90 mmHg OR downward-trending where symptomatic ·
# Pulse ≤40 or ≥131 · GCS <13 (new for patient)
SOGLIE_ADULTO = {
    "rr_bassa": 8, "rr_alta": 25,
    "spo2_su_o2": 91, "spo2_su_o2_ipercapnico": 83,
    "sbp": 90,
    "hr_bassa": 40, "hr_alta": 131,
    "gcs": 13,
}

# ── 2. Fisiologia alterata nel BAMBINO («Adapted from PEWS») — tabella trascritta ───────────
# fascia: (età_min_anni inclusa, età_max_anni esclusa, RR (bassa,alta), HR (bassa,alta))
# RR: <20 or >60 | <20 or >50 | <15 or >40 | <10 or >30
# HR: <90 or >170 | <70 or >150 | <70 or >140 | <60 or >120
# SpO2 <91% on air (tutte le fasce) · CRT ≥3 s · GCS <13 (modified GCS sotto i 5 anni) ·
# Temperatura ≥38 °C se età <3 mesi
FASCE_PEDIATRICHE = (
    {"nome": "<1 anno",    "eta_min": 0,  "eta_max": 1,  "rr": (20, 60), "hr": (90, 170)},
    {"nome": "1-4 anni",   "eta_min": 1,  "eta_max": 5,  "rr": (20, 50), "hr": (70, 150)},
    {"nome": "5-12 anni",  "eta_min": 5,  "eta_max": 13, "rr": (15, 40), "hr": (70, 140)},
    {"nome": "13-15 anni", "eta_min": 13, "eta_max": 16, "rr": (10, 30), "hr": (60, 120)},
)
SOGLIE_PEDIATRICHE = {"spo2_aria": 91, "crt_sec": 3, "gcs": 13, "temp_lattante": 38.0, "mesi_lattante": 3}

# ── 3. Condizioni specifiche (elenco trascritto; chiave → riga della linea guida) ───────────
CONDIZIONI_SPECIFICHE = {
    "arresto_cardiaco_o_respiratorio": "Cardiac/Respiratory arrest",
    "compromissione_vie_aeree": "Airway compromise",
    "trauma_maggiore_step_1_2": "Positive for Step 1 or Step 2 of the Major Trauma Triage Tool (local tool)",
    "stemi": "ST elevation MI — follow local policies for PPCI",
    "blocco_av_completo_o_tv_larga_con_segni_avversi": ("Complete heart block or broad complex tachycardia "
                                                         "with adverse features (shock, syncope, heart failure, "
                                                         "myocardial ischaemia)"),
    "ictus_fast_positivo_in_finestra": "FAST-positive stroke within the timeframe for thrombolysis",
    "sepsi_alto_rischio_adulto": "Adults with suspected 'high risk sepsis' as per JRCALC (see sepsi_alto_rischio_jrcalc)",
    "sepsi_alto_rischio_pediatrica": "Children with 'high risk criteria' for sepsis (JRCALC, per age band)",
    "crisi_convulsiva_in_atto": "Uncontrolled seizure - still fitting",
    "emergenza_gravidanza_precoce": "Early pregnancy emergencies, e.g. suspected ruptured ectopic",
    "asma_pericolo_di_vita": "Life-threatening asthma",
    "disturbo_comportamentale_acuto": "Acute behavioural disturbance",
    "chetoacidosi_diabetica_sospetta": "Suspected diabetic ketoacidosis",
    "emorragia_maggiore_non_controllata": "Uncontrolled major haemorrhage",
    "overdose_con_fisiologia_alterata": ("Overdose with abnormal physiology and possible lethality, "
                                         "which may require immediate intervention on arrival"),
    "emergenza_vascolare_con_shock": ("Suspected vascular emergency e.g. AAA or thoracic dissection with "
                                      "signs of shock, acute limb ischaemia"),
    "deterioramento_rapido_o_preoccupazione_clinica": ("Any rapidly deteriorating patient or significant "
                                                       "concern in the view of the ambulance clinician"),
}

# ── 4. Sepsi ad alto rischio nell'adulto (Appendix 1, adattata da JRCALC+) ─────────────────
# «A NEWS2 score ≥5 should prompt suspicion of sepsis and urgent clinical review, but it is not
# diagnostic.» I marcatori valgono «in an unwell patient, with history of infection».
SEGNI_SEPSI = {
    "confusione_nuova_o_risponde_solo_a_voce_dolore_o_non_risponde": "New onset of confusion / responds only to voice or pain / unresponsive",
    "cute_marezzata_o_cinerea": "Reduction in normal skin colour (mottled or ashen)",
    "rash_non_sbiancante": "Non-blanching rash (petechial or purpuric)",
    "cianosi": "Cyanosis of skin, lips or tongue",
    "nessuna_minzione_18h": "Not passed urine in last 18 hours",
    "chemioterapia_ultime_6_settimane": "Recent chemotherapy (in past 6 weeks)",
    "calo_sbp_40_dal_normale": "Systolic BP drop ≥40 from normal",
}
SOGLIE_SEPSI = {"sbp": 90, "map": 65, "hr": 130, "rr": 25, "spo2_target": 92, "spo2_target_bpco": 88, "news2": 5}

_NUM = (int, float)


def _num(v) -> bool:
    return isinstance(v, _NUM) and not isinstance(v, bool) and v == v


def _flags(d: Optional[Dict], ammessi, nome: str) -> List[str]:
    """Validazione dei dizionari di flag: solo booleani JSON, solo chiavi note. Ritorna i problemi."""
    if d is None:
        return []
    if not isinstance(d, dict):
        return [f"{nome} non è un oggetto (ricevuto {type(d).__name__})"]
    p = []
    for k, v in d.items():
        if k not in ammessi:
            p.append(f"{nome}.{k}: campo non riconosciuto (rifiutato, non ignorato)")
        elif not isinstance(v, bool):
            p.append(f"non booleano: {nome}.{k}={v!r} (atteso true/false JSON)")
    return p


def criteri_adulto(vitali: Dict, gcs: Optional[int] = None, gcs_abituale: Optional[int] = None) -> Dict:
    """Fisiologia alterata nell'adulto (≥16 anni). `vitali` nello schema del companion
    (rr, spo2, su_ossigeno, sbp, hr, alert_coscienza, temp, bpco_scala2 opzionale)."""
    S = SOGLIE_ADULTO
    crit: List[Dict] = []
    rr, spo2, sbp, hr = vitali["rr"], vitali["spo2"], vitali["sbp"], vitali["hr"]
    if rr <= S["rr_bassa"] or rr >= S["rr_alta"]:
        crit.append({"criterio": "frequenza respiratoria", "valore": rr,
                     "soglia": f"≤{S['rr_bassa']} o ≥{S['rr_alta']}"})
    if vitali.get("su_ossigeno"):
        lim = S["spo2_su_o2_ipercapnico"] if vitali.get("bpco_scala2") else S["spo2_su_o2"]
        if spo2 <= lim:
            crit.append({"criterio": "SpO2 in ossigeno", "valore": spo2, "soglia": f"≤{lim}%"
                         + (" (insufficienza ipercapnica cronica)" if vitali.get("bpco_scala2") else "")})
    if sbp <= S["sbp"]:
        crit.append({"criterio": "pressione sistolica", "valore": sbp, "soglia": f"≤{S['sbp']} mmHg"})
    if hr <= S["hr_bassa"] or hr >= S["hr_alta"]:
        crit.append({"criterio": "frequenza cardiaca", "valore": hr,
                     "soglia": f"≤{S['hr_bassa']} o ≥{S['hr_alta']}"})
    if gcs is not None and gcs < S["gcs"]:
        # «GCS <13 (new for patient)»: se è noto il GCS abituale e quello attuale non è peggiore, NON è
        # nuovo (paziente con danno neurologico cronico: falso positivo sistematico, council 13/09).
        if gcs_abituale is not None and gcs >= gcs_abituale:
            pass
        else:
            crit.append({"criterio": "GCS", "valore": gcs, "soglia": f"<{S['gcs']}" + (
                " (nuovo: peggiore del GCS abituale)" if gcs_abituale is not None else
                " (la linea guida: 'new for patient' — GCS abituale non fornito: criterio attivato in modo conservativo)")})
    nv = ["pressione sistolica in calo con sintomi (serve una serie di misure, qui una sola)"]
    if gcs_abituale is None:
        nv.append("GCS 'nuovo per il paziente' (fornire clinica.gcs_abituale per escludere un deficit cronico)")
    if not vitali.get("su_ossigeno") and spo2 < 92:
        nv.append(f"SpO2 {spo2}% IN ARIA: la linea guida adulti fissa soglie solo IN OSSIGENO; il NEWS2 la copre "
                  "(SpO2 ≤91 = 3 punti) — valutare ossigeno e rimisurare")
    return {"criteri": crit, "non_valutato": nv}


def _fascia(eta_anni: float) -> Optional[Dict]:
    for f in FASCE_PEDIATRICHE:
        if f["eta_min"] <= eta_anni < f["eta_max"]:
            return f
    return None


def valida_vitali_pediatrici(v: Dict) -> List[str]:
    """Stessa disciplina degli adulti: numeri veri, flag booleani, chiavi note, range plausibili."""
    if not isinstance(v, dict):
        return [f"vitali non è un oggetto (ricevuto {type(v).__name__})"]
    attesi = {"rr": (0, 150), "hr": (0, 300), "spo2": (30, 100)}
    opz = {"crt_sec": (0, 30), "gcs": (3, 15), "temp": (25, 45), "sbp": (0, 300)}
    p = [f"campo mancante: {k}" for k in attesi if k not in v]
    if "su_ossigeno" not in v:
        p.append("campo mancante: su_ossigeno (SpO2 <91% vale IN ARIA)")
    for k in ("su_ossigeno", "alert_coscienza", "bpco_scala2"):
        if k in v and not isinstance(v[k], bool):
            p.append(f"non booleano: {k}={v[k]!r} (atteso true/false JSON)")
    for k in v:
        if k not in attesi and k not in opz and k not in ("su_ossigeno", "alert_coscienza", "bpco_scala2"):
            p.append(f"vitali.{k}: campo non riconosciuto")
    for k, (lo, hi) in {**attesi, **opz}.items():
        if k in v:
            x = v[k]
            if not _num(x):
                p.append(f"non numerico: {k}={x!r} (atteso numero JSON)")
            elif not (lo <= x <= hi):
                p.append(f"fuori range plausibile: {k}={x!r} (atteso {lo}-{hi})")
    if "gcs" in v and _num(v["gcs"]) and not float(v["gcs"]).is_integer():
        p.append(f"gcs non intero: {v['gcs']!r}")
    return p


def criteri_pediatrici(eta_anni: float, vitali: Dict, eta_mesi: Optional[int] = None) -> Dict:
    """Criteri di pre-alert per fasce d'età (<16). NON è un punteggio pediatrico."""
    problemi = valida_vitali_pediatrici(vitali)
    if eta_mesi is not None:
        if not _num(eta_mesi) or not (0 <= eta_mesi <= 11):
            problemi.append(f"eta_mesi non valida: {eta_mesi!r} (atteso 0-11, solo sotto l'anno)")
        elif eta_anni >= 1:
            problemi.append(f"eta_mesi={eta_mesi!r} incoerente con eta={eta_anni!r} (i mesi valgono solo sotto l'anno)")
    if problemi:
        return {"criteri": [], "problemi_dati": problemi, "fascia": None}
    f = _fascia(eta_anni)
    if f is None:
        return {"criteri": [], "problemi_dati": [f"età {eta_anni} fuori dalle fasce pediatriche (0-15)"], "fascia": None}
    P = SOGLIE_PEDIATRICHE
    crit: List[Dict] = []
    rr, hr = vitali["rr"], vitali["hr"]
    if rr < f["rr"][0] or rr > f["rr"][1]:
        crit.append({"criterio": "frequenza respiratoria", "valore": rr, "soglia": f"<{f['rr'][0]} o >{f['rr'][1]} ({f['nome']})"})
    if hr < f["hr"][0] or hr > f["hr"][1]:
        crit.append({"criterio": "frequenza cardiaca", "valore": hr, "soglia": f"<{f['hr'][0]} o >{f['hr'][1]} ({f['nome']})"})
    if not vitali["su_ossigeno"] and vitali["spo2"] < P["spo2_aria"]:
        crit.append({"criterio": "SpO2 in aria", "valore": vitali["spo2"], "soglia": f"<{P['spo2_aria']}%"})
    if "crt_sec" in vitali and vitali["crt_sec"] >= P["crt_sec"]:
        crit.append({"criterio": "tempo di riempimento capillare", "valore": vitali["crt_sec"], "soglia": f"≥{P['crt_sec']} s"})
    if "gcs" in vitali and vitali["gcs"] < P["gcs"]:
        crit.append({"criterio": "GCS" + (" modificato" if eta_anni < 5 else ""), "valore": vitali["gcs"], "soglia": f"<{P['gcs']}"})
    if eta_mesi is not None and eta_mesi < P["mesi_lattante"] and "temp" in vitali and vitali["temp"] >= P["temp_lattante"]:
        crit.append({"criterio": "temperatura (lattante <3 mesi)", "valore": vitali["temp"], "soglia": f"≥{P['temp_lattante']} °C"})
    non_val = []
    if vitali["su_ossigeno"]:
        non_val.append(f"SpO2 {vitali['spo2']}% IN OSSIGENO: la tabella pediatrica vale IN ARIA (<91%); "
                       "un bambino che richiede ossigeno va comunque discusso col PS")
    if "crt_sec" not in vitali:
        non_val.append("tempo di riempimento capillare (non fornito)")
    if "gcs" not in vitali:
        non_val.append("GCS (non fornito)")
    if eta_mesi is None and eta_anni < 1:
        non_val.append("temperatura ≥38 °C sotto i 3 mesi (eta_mesi non fornita)")
    return {"criteri": crit, "problemi_dati": [], "fascia": f["nome"], "non_valutato": non_val,
            "nota": "criteri di pre-alert per fascia d'età (PEWS-adattati), NON uno score: NEWS2 resta rifiutato <16"}


def sepsi_alto_rischio_jrcalc(vitali: Dict, segni: Optional[Dict], storia_infezione: bool,
                              news2: Optional[int] = None, map_mmhg: Optional[float] = None) -> Dict:
    """Marcatori di 'high risk sepsis' (Appendix 1). Valgono solo con storia di infezione: senza,
    i marcatori vengono elencati ma NON classificati come sepsi ad alto rischio (dichiarato)."""
    problemi = _flags(segni, SEGNI_SEPSI, "segni_sepsi")
    if not isinstance(storia_infezione, bool):
        problemi.append(f"non booleano: storia_infezione={storia_infezione!r}")
    if map_mmhg is not None and not _num(map_mmhg):
        problemi.append(f"non numerico: map_mmhg={map_mmhg!r}")
    if problemi:
        return {"alto_rischio": False, "marcatori": [], "problemi_dati": problemi}
    T = SOGLIE_SEPSI
    m: List[str] = []
    sg = segni or {}
    non_val: List[str] = []
    if "alert_coscienza" not in vitali and not sg.get("confusione_nuova_o_risponde_solo_a_voce_dolore_o_non_risponde"):
        non_val.append("stato di coscienza (alert_coscienza assente): marcatore confusione non valutato")
    if sg.get("confusione_nuova_o_risponde_solo_a_voce_dolore_o_non_risponde") or not vitali.get("alert_coscienza", True):
        m.append(SEGNI_SEPSI["confusione_nuova_o_risponde_solo_a_voce_dolore_o_non_risponde"])
    if vitali["sbp"] <= T["sbp"] or sg.get("calo_sbp_40_dal_normale") or (map_mmhg is not None and map_mmhg < T["map"]):
        m.append(f"Systolic BP ≤{T['sbp']} (or drop ≥40 from normal) or MAP <{T['map']}")
    if vitali["hr"] >= T["hr"]:
        m.append(f"Heart rate ≥{T['hr']}")
    if vitali["rr"] >= T["rr"]:
        m.append(f"Respiratory rate ≥{T['rr']}")
    # «Needs oxygen to keep SpO2 ≥92% (or more than 88% in known COPD)»: il marcatore è il BISOGNO di
    # ossigeno. Prima (bug trovato dal council 13/09) scattava solo se in O2 la SpO2 era ≥ target, cioè
    # sul paziente che regge e NON su quello che in O2 resta sotto (il più grave). Ora: in ossigeno =
    # marcatore; se in ossigeno è ancora sotto il target, lo dice.
    if vitali.get("su_ossigeno"):
        bpco = bool(vitali.get("bpco_scala2"))
        sotto = (vitali["spo2"] <= T["spo2_target_bpco"]) if bpco else (vitali["spo2"] < T["spo2_target"])
        m.append("Needs oxygen to keep SpO2 " + (">88% (known COPD)" if bpco else "≥92%")
                 + (" — AND still below target on oxygen" if sotto else ""))
    for k in ("cute_marezzata_o_cinerea", "rash_non_sbiancante", "cianosi", "nessuna_minzione_18h",
              "chemioterapia_ultime_6_settimane"):
        if sg.get(k):
            m.append(SEGNI_SEPSI[k])
    out = {"marcatori": m, "storia_infezione": storia_infezione, "non_valutato": non_val,
           "alto_rischio": bool(m) and storia_infezione,
           "nota": ("NEWS2 ≥5 suggerisce il sospetto ma NON è diagnostico (linea guida); i marcatori valgono "
                    "in un paziente con storia di infezione")}
    if news2 is not None:
        out["news2_sospetto"] = news2 >= T["news2"]
    if m and not storia_infezione:
        out["nota"] += " — marcatori presenti ma storia di infezione assente: NON classificato alto rischio"
    return out


def decisione_prealert(eta: float, vitali: Dict, gcs: Optional[int] = None,
                       condizioni: Optional[Dict] = None, eta_mesi: Optional[int] = None,
                       sepsi: Optional[Dict] = None, crt_sec: Optional[float] = None,
                       gcs_abituale: Optional[int] = None, note_derivazione: Optional[Dict] = None) -> Dict:
    """Il pre-alert è indicato dalla linea guida? Ritorna criteri, condizioni, scope e fonte.
    `condizioni`: dict di booleani con chiavi di CONDIZIONI_SPECIFICHE. `sepsi`: output di
    sepsi_alto_rischio_jrcalc (opzionale: se alto_rischio True conta come condizione specifica)."""
    problemi = _flags(condizioni, CONDIZIONI_SPECIFICHE, "condizioni")
    for nome, g in (("gcs", gcs), ("gcs_abituale", gcs_abituale)):
        if g is not None and (isinstance(g, bool) or not isinstance(g, int) or not (3 <= g <= 15)):
            problemi.append(f"{nome} non valido: {g!r} (atteso intero 3-15)")
    if crt_sec is not None and (not _num(crt_sec) or not (0 <= crt_sec <= 30)):
        problemi.append(f"crt_sec non valido: {crt_sec!r} (atteso numero 0-30 secondi)")
    if not _num(eta) or not (0 <= eta <= 130):
        problemi.append(f"eta non valida: {eta!r}")
    if problemi:
        return {"pre_alert_indicato": None, "problemi_dati": problemi, "fonte": FONTE}
    pediatrico = eta < 16
    if pediatrico:
        # gcs e crt_sec arrivano da `clinica` (non da vitali, che li rifiuta per nome): entrano qui
        # (bug trovato dal council 13/09: bambino con GCS 8 o CRT 5 s e FR/FC normali usciva «nessun pre-alert»)
        vp = dict(vitali)
        if gcs is not None:
            vp["gcs"] = gcs
        if crt_sec is not None:
            vp["crt_sec"] = crt_sec
        fis = criteri_pediatrici(eta, vp, eta_mesi)
    else:
        import barella_prealert as B
        p = B.valida_vitali(vitali)
        if p:
            return {"pre_alert_indicato": None, "problemi_dati": p, "fonte": FONTE}
        fis = criteri_adulto(vitali, gcs, gcs_abituale)
    if fis.get("problemi_dati"):
        return {"pre_alert_indicato": None, "problemi_dati": fis["problemi_dati"], "fonte": FONTE}
    cond = [{"condizione": k, "linea_guida": CONDIZIONI_SPECIFICHE[k],
             **({"derivazione": note_derivazione[k]} if note_derivazione and k in note_derivazione else {})}
            for k, v in (condizioni or {}).items() if v]
    if sepsi and sepsi.get("alto_rischio") and not any(c["condizione"].startswith("sepsi") for c in cond):
        cond.append({"condizione": "sepsi_alto_rischio_adulto", "linea_guida": CONDIZIONI_SPECIFICHE["sepsi_alto_rischio_adulto"],
                     "marcatori": sepsi.get("marcatori")})
    indicato = bool(fis["criteri"]) or bool(cond)
    return {
        "pre_alert_indicato": indicato,
        "pediatrico": pediatrico, "fascia": fis.get("fascia"),
        "criteri_fisiologici": fis["criteri"], "condizioni_specifiche": cond,
        "non_valutato": fis.get("non_valutato", []),
        "regola": ("«Calls for information only ('heads up' calls) must be avoided» — il pre-alert va fatto "
                   "solo se attiva una risposta specifica; la risposta effettiva la decide il senior clinico "
                   "del PS, e una risposta alternativa NON è un fallimento del pre-alert (linea guida 2025)"),
        "fonte": FONTE,
    }


def messaggio_prealert(decisione: Dict, eta_arrivo_min: float, richiesta_risposta: str,
                       atmist: Dict, ora_arrivo_hhmm: Optional[str] = None) -> Dict:
    """Ordine prescritto: headline concern + ETA PRIMA («in case the call gets cut off»), poi ATMIST
    «as quickly as possible and without interruption». Stima della durata: parlato ~150 parole/min
    (euristica dichiarata, non misura): la linea guida chiede ≤60 s."""
    if not _num(eta_arrivo_min) or not (0 <= eta_arrivo_min <= 600):
        raise ValueError("eta_arrivo_min non valido")
    motivi = [c["criterio"] for c in decisione.get("criteri_fisiologici", [])] + \
             [c["condizione"].replace("_", " ") for c in decisione.get("condizioni_specifiche", [])]
    headline = (f"{richiesta_risposta.strip()[:60] or 'pre-alert'} — motivo: {', '.join(motivi) or 'preoccupazione clinica'}"
                f" — ETA {ora_arrivo_hhmm or f'+{int(round(eta_arrivo_min))} min'}")
    a = atmist.get("ATMIST", atmist)
    corpo = (f"A: {a.get('A_eta')} · T: {a.get('T_orario_evento')} · M: {a.get('M_meccanismo_esordio')} · "
             f"I: {a.get('I_lesioni_problema')} · S: {a.get('S_segni')} · "
             f"T: {', '.join(a.get('T_trattamenti') or []) or 'nessuno'}")
    testo = f"HEADLINE: {headline}. ATMIST — {corpo}"
    parole = len(testo.split())
    secondi_stimati = round(parole / 2.5, 1)          # 150 parole/min
    return {"testo": testo, "headline": headline, "atmist": corpo, "parole": parole,
            "secondi_stimati": secondi_stimati, "entro_60s": secondi_stimati <= 60,
            "nota": "stima a 150 parole/min (euristica dichiarata); la linea guida chiede ≤60 s, headline ed ETA per primi"}


# ── banco che SA FALLIRE ────────────────────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    stabile = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72, alert_coscienza=True, temp=36.7)
    critico = dict(rr=26, spo2=90, su_ossigeno=True, sbp=88, hr=135, alert_coscienza=False, temp=39.0)
    # null: adulto stabile senza condizioni → NESSUN pre-alert (la linea guida vieta gli «heads up»)
    d0 = decisione_prealert(40, stabile)
    # positivo: adulto con 4 criteri fisiologici
    d1 = decisione_prealert(67, critico, gcs=12)
    # positivo per condizione sola (vitali normali + STEMI)
    d2 = decisione_prealert(60, stabile, condizioni={"stemi": True})
    # pediatrico: lattante 6 mesi con FR 65 e SpO2 88 in aria → 2 criteri, NESSUNO score
    d3 = decisione_prealert(0, dict(rr=65, hr=150, spo2=88, su_ossigeno=False), eta_mesi=6)
    # pediatrico stabile 8 anni → nessun criterio
    d4 = decisione_prealert(8, dict(rr=22, hr=95, spo2=98, su_ossigeno=False, crt_sec=1, gcs=15))
    # tipi ostili: stringa dove serve un booleano, chiave ignota → rifiuto nominato
    d5 = decisione_prealert(50, stabile, condizioni={"stemi": "no"})
    d6 = decisione_prealert(50, stabile, condizioni={"infarto": True})
    # sepsi: marcatori senza storia di infezione → NON alto rischio; con storia → alto rischio
    s0 = sepsi_alto_rischio_jrcalc(critico, {"cianosi": True}, storia_infezione=False)
    s1 = sepsi_alto_rischio_jrcalc(critico, {"cianosi": True}, storia_infezione=True)
    ok = (d0["pre_alert_indicato"] is False
          and d1["pre_alert_indicato"] is True and len(d1["criteri_fisiologici"]) == 5
          and d2["pre_alert_indicato"] is True and not d2["criteri_fisiologici"]
          and d3["pre_alert_indicato"] is True and len(d3["criteri_fisiologici"]) == 2 and "NEWS2" not in d3
          and d4["pre_alert_indicato"] is False
          and d5["pre_alert_indicato"] is None and d6["pre_alert_indicato"] is None
          and s0["alto_rischio"] is False and s1["alto_rischio"] is True)
    return {"banco_sa_fallire": ok, "null_adulto_stabile": d0["pre_alert_indicato"],
            "positivo_adulto_criteri": len(d1["criteri_fisiologici"]),
            "positivo_condizione": d2["pre_alert_indicato"], "pediatrico_criteri": len(d3["criteri_fisiologici"]),
            "tipi_ostili_rifiutati": d5["pre_alert_indicato"] is None and d6["pre_alert_indicato"] is None,
            "sepsi_richiede_storia": s0["alto_rischio"] is False and s1["alto_rischio"] is True,
            "fonte": FONTE["linea_guida"]}


if __name__ == "__main__":
    import json
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
