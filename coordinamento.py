#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""coordinamento — ciò che i competitor fanno e health non faceva, nello stile OMEGA (13/09/2026).

Confronto letto online il 13/09/2026 (Pulsara, Twiage/TigerConnect EMS, corpuls.mission LIVE, NIDA):
tipi di paziente → team da allertare; ETA e posizione aggiornate in corsa; messaggi bidirezionali
equipaggio↔PS; immagini/ECG condivisi; «close the loop» (esito clinico dopo l'arrivo); metriche di
qualità QA/QI; incidenti maggiori con più pazienti. Qui ognuno è implementato con la regola di casa:
valori chiusi o digest nel ledger, testo libero e byte SOLO in memoria con scadenza, ogni evento
firmato (audit_bridge), mai un dato sanitario su disco.

Fuori perimetro, dichiarato: chiamate audio/video (infrastruttura, non evidenza); ricerca dell'identità
del paziente nell'anagrafica ospedaliera (health è PII-free per progetto); export NEMSIS (standard USA:
in Europa la strada è FHIR, già presente).
"""
from __future__ import annotations
import hashlib
import statistics
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ── 1. Tipo di paziente → team da allertare (come i «patient types» di Pulsara, ma derivati dai
#       percorsi già calcolati e dalle condizioni 2025, nel vocabolario chiuso delle risposte) ──────
TIPI = {
    "arresto_cardiaco": ("resus", "Sudden cardiac arrest / peri-arrest"),
    "stemi": ("cath_lab", "STEMI — PPCI"),
    "ictus": ("stroke_team", "Stroke (FAST+)"),
    "trauma_maggiore": ("trauma_team", "Major trauma"),
    "sepsi": ("percorso_sepsi", "Sepsis (JRCALC high risk / qSOFA)"),
    "pediatrico": ("percorso_pediatrico", "Paediatric"),
    "ostetrico": ("percorso_ostetrico", "Obstetric / early pregnancy emergency"),
    "tossicologico": ("revisione_senior_immediata", "Toxicology / overdose with abnormal physiology"),
    "vascolare": ("revisione_senior_immediata", "Vascular emergency with shock"),
    "comportamentale": ("revisione_senior_immediata", "Acute behavioural disturbance"),
    "metabolico": ("revisione_senior_immediata", "Suspected DKA"),
    "respiratorio_critico": ("resus", "Airway compromise / life-threatening asthma"),
    "emorragia": ("trauma_team", "Uncontrolled major haemorrhage"),
    "generale": ("nessuna_risposta_specifica", "General"),
}
_COND2TIPO = {
    "arresto_cardiaco_o_respiratorio": "arresto_cardiaco", "compromissione_vie_aeree": "respiratorio_critico",
    "trauma_maggiore_step_1_2": "trauma_maggiore", "stemi": "stemi",
    "blocco_av_completo_o_tv_larga_con_segni_avversi": "arresto_cardiaco",
    "ictus_fast_positivo_in_finestra": "ictus", "sepsi_alto_rischio_adulto": "sepsi",
    "sepsi_alto_rischio_pediatrica": "pediatrico", "crisi_convulsiva_in_atto": "respiratorio_critico",
    "emergenza_gravidanza_precoce": "ostetrico", "asma_pericolo_di_vita": "respiratorio_critico",
    "disturbo_comportamentale_acuto": "comportamentale", "chetoacidosi_diabetica_sospetta": "metabolico",
    "emorragia_maggiore_non_controllata": "emorragia", "overdose_con_fisiologia_alterata": "tossicologico",
    "emergenza_vascolare_con_shock": "vascolare",
}


def classifica_tipo(prealert: Dict) -> Dict:
    """Da un PRE_ALERT_INTEGRATO ai tipi di paziente e ai team da allertare (ordine = priorità clinica).
    Deterministico, dai soli flag già calcolati: nessuna inferenza nuova."""
    tipi: List[str] = []
    if prealert.get("priorita") == "NON_VALUTABILE_PEDIATRICO":
        tipi.append("pediatrico")
    if prealert.get("arresto") or prealert.get("arresto_respiratorio"):
        tipi.append("arresto_cardiaco")
    if prealert.get("cardio") and any("STEMI" in p for p in prealert.get("percorsi_attivare") or []):
        tipi.append("stemi")
    if prealert.get("BE_FAST"):
        tipi.append("ictus")
    if prealert.get("trauma_team"):
        tipi.append("trauma_maggiore")
    if any("SEPSI" in p for p in prealert.get("percorsi_attivare") or []) or (prealert.get("sepsi_jrcalc") or {}).get("alto_rischio"):
        tipi.append("sepsi")
    for c in (prealert.get("criteri_prealert_2025") or {}).get("condizioni_specifiche") or []:
        t = _COND2TIPO.get(c.get("condizione"))
        if t and t not in tipi:
            tipi.append(t)
    if not tipi:
        tipi.append("generale")
    team, visti = [], set()
    for t in tipi:
        r = TIPI[t][0]
        if r not in visti:
            team.append(r)
            visti.add(r)
    return {"tipi": tipi, "descrizioni": [TIPI[t][1] for t in tipi], "team_da_allertare": team,
            "nota": "tipi derivati dai percorsi/condizioni già calcolati; il team effettivo lo decide il PS"}


# ── 2. ETA e posizione in corsa ────────────────────────────────────────────────────────────
def valida_posizione(lat, lon, eta_arrivo_min) -> List[str]:
    p = []
    for nome, v, lo, hi in (("lat", lat, -90, 90), ("lon", lon, -180, 180), ("eta_arrivo_min", eta_arrivo_min, 0, 600)):
        if v is None:
            if nome == "eta_arrivo_min":
                p.append("eta_arrivo_min mancante")
            continue
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or not (lo <= v <= hi):
            p.append(f"{nome} non valido: {v!r} (atteso numero {lo}..{hi})")
    if (lat is None) != (lon is None):
        p.append("lat e lon vanno insieme")
    return p


def evento_posizione(lat, lon, eta_arrivo_min) -> Dict:
    """Ciò che va nel ledger: ETA e DIGEST della posizione (council 13/09: nemmeno ~1 km su disco — la
    prima posizione è la scena). La posizione esatta resta in memoria per il PS; chi ha la posizione può
    provare che è quella, chi ha il disco non legge dove."""
    return {"eta_arrivo_min": eta_arrivo_min,
            "posizione_sha256": (hashlib.sha256(f"{lat:.5f},{lon:.5f}".encode()).hexdigest() if lat is not None else None),
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}


# ── 3. Messaggi bidirezionali ─────────────────────────────────────────────────────────────
MITTENTI = ("equipaggio", "ps")
MAX_MESSAGGIO = 300


def valida_messaggio(da: str, operatore: str, testo: str) -> List[str]:
    p = []
    if da not in MITTENTI:
        p.append(f"da non ammesso: {da!r} (ammessi: {', '.join(MITTENTI)})")
    if not isinstance(operatore, str) or not operatore.strip() or len(operatore) > 60:
        p.append("operatore: stringa 1-60 caratteri")
    if not isinstance(testo, str) or not testo.strip() or len(testo) > MAX_MESSAGGIO:
        p.append(f"testo: stringa 1-{MAX_MESSAGGIO} caratteri")
    return p


def impronta_testo(testo: str) -> Dict:
    return {"sha256": hashlib.sha256(testo.encode("utf-8")).hexdigest(), "lunghezza": len(testo)}


# ── 4. Allegati (ECG, foto della scena, documenti) ───────────────────────────────────────
TIPI_ALLEGATO = ("ecg", "foto", "documento")
CONTENT_TYPES = ("image/png", "image/jpeg", "application/pdf", "application/xml", "text/xml", "text/plain")
MAX_ALLEGATO = 2 * 1024 * 1024
_MAGIC = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff", "application/pdf": b"%PDF-"}


def valida_allegato(tipo: str, content_type: str, raw: bytes) -> List[str]:
    p = []
    if tipo not in TIPI_ALLEGATO:
        p.append(f"tipo non ammesso: {tipo!r} (ammessi: {', '.join(TIPI_ALLEGATO)})")
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct not in CONTENT_TYPES:
        p.append(f"content-type non ammesso: {ct!r}")
    if not raw:
        p.append("allegato vuoto")
    elif len(raw) > MAX_ALLEGATO:
        p.append(f"allegato troppo grande: {len(raw)} byte (max {MAX_ALLEGATO})")
    magic = _MAGIC.get(ct)
    if magic and raw and not raw.startswith(magic):
        p.append(f"il contenuto non è {ct} (firma dei byte diversa dal content-type dichiarato)")
    return p


def descrivi_allegato(tipo: str, content_type: str, raw: bytes) -> Dict:
    return {"tipo": tipo, "content_type": content_type.split(";")[0].strip().lower(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "nota": "byte in memoria con la bacheca (scadenza); nel ledger solo il digest; nessuna interpretazione automatica"}


# ── 5. Close the loop: esito clinico dopo l'arrivo ──────────────────────────────────────
ESITI = ("percorso_confermato", "percorso_non_necessario", "percorso_diverso", "paziente_deceduto",
         "trasferito_altro_centro", "dimesso", "altro")


def valida_esito(operatore_ps: str, esito: str, diagnosi_confermata, tempo_porta_intervento_min) -> List[str]:
    p = []
    if not isinstance(operatore_ps, str) or not operatore_ps.strip() or len(operatore_ps) > 60:
        p.append("operatore_ps: stringa 1-60 caratteri")
    if esito not in ESITI:
        p.append(f"esito non ammesso: {esito!r} (ammessi: {', '.join(ESITI)})")
    if diagnosi_confermata is not None and not isinstance(diagnosi_confermata, bool):
        p.append(f"non booleano: diagnosi_confermata={diagnosi_confermata!r}")
    t = tempo_porta_intervento_min
    if t is not None and (isinstance(t, bool) or not isinstance(t, (int, float)) or t != t or not (0 <= t <= 1440)):
        p.append(f"tempo_porta_intervento_min non valido: {t!r} (atteso 0-1440)")
    return p


# ── 6. Metriche QA/QI (aggregate, senza PII) ─────────────────────────────────────────────
def metriche(board: List[Dict]) -> Dict:
    """Aggregati sulla bacheca in memoria: volumi, latenze, risposte alternative, esiti, over/under-triage
    come PROXY (pre-alert indicato dai criteri 2025 vs esito). Nessun identificativo."""
    n = len(board)
    prio: Dict[str, int] = {}
    lat: List[float] = []
    alt = ric = esiti_n = 0
    esiti: Dict[str, int] = {}
    over = under = conf = 0
    tempi: List[float] = []
    for r in board:
        pa = r.get("prealert") or {}
        prio[pa.get("priorita", "SCADUTO")] = prio.get(pa.get("priorita", "SCADUTO"), 0) + 1
        for x in r.get("ricezioni") or []:
            ric += 1
            if x.get("latenza_s") is not None:
                lat.append(x["latenza_s"])
            if x.get("risposta_alternativa"):
                alt += 1
        for e in r.get("esiti") or []:
            esiti_n += 1
            esiti[e["esito"]] = esiti.get(e["esito"], 0) + 1
            if e.get("tempo_porta_intervento_min") is not None:
                tempi.append(e["tempo_porta_intervento_min"])
        # over/under-triage: UNA volta per pre-alert, sull'ULTIMO esito registrato (council 13/09: prima
        # ogni esito contava, doppio conteggio se un pre-alert ne aveva più d'uno)
        ultimi = r.get("esiti") or []
        if ultimi:
            e = ultimi[-1]
            indicato = (pa.get("criteri_prealert_2025") or {}).get("pre_alert_indicato")
            if indicato is True and e["esito"] == "percorso_non_necessario":
                over += 1
            if indicato is False and e["esito"] == "percorso_confermato":
                under += 1
            if e["esito"] == "percorso_confermato":
                conf += 1
    # escalation su mancata ricezione (Pulsara: ri-allerta se nessuno prende la chiamata): pre-alert vivi
    # senza alcuna ricezione oltre ESCALATION_S dall'emissione
    now = datetime.now(timezone.utc)
    da_escalare = []
    for r in board:
        if r.get("prealert") is None or r.get("ricezioni"):
            continue
        try:
            eta_s = (now - datetime.fromisoformat(r["ts"])).total_seconds()
        except (KeyError, ValueError):
            continue
        if eta_s > ESCALATION_S:
            da_escalare.append({"id": r["id"], "secondi_senza_ricezione": int(eta_s)})
    return {
        "pre_alert": n, "per_priorita": prio, "ricezioni": ric,
        "da_escalare": da_escalare, "escalation_dopo_s": ESCALATION_S,
        "latenza_ricezione_s": ({"mediana": statistics.median(lat), "max": max(lat), "n": len(lat)} if lat else None),
        "risposte_alternative": alt, "quota_risposte_alternative": (round(alt / ric, 3) if ric else None),
        "esiti": esiti, "esiti_registrati": esiti_n,
        "tempo_porta_intervento_min": ({"mediana": statistics.median(tempi), "n": len(tempi)} if tempi else None),
        "over_triage_proxy": over, "under_triage_proxy": under, "percorsi_confermati": conf,
        "nota": ("proxy: over = pre-alert indicato dai criteri 2025 ma percorso non necessario; under = non indicato ma "
                 "percorso confermato; sono conteggi sulla bacheca in memoria, non un audit clinico"),
    }


ESCALATION_S = 120          # nessuna ricezione entro 2 minuti dall'emissione → da escalare (dichiarato, configurabile)

# ── 6b. Stato del PS: accetta / saturo / dirotta (divert) — a vocabolario chiuso, firmato ──────
STATI_PS = ("accetta", "saturo", "dirotta")


def valida_stato_ps(stato: str, operatore_ps: str, destinazione_alternativa: Optional[str]) -> List[str]:
    p = []
    if stato not in STATI_PS:
        p.append(f"stato non ammesso: {stato!r} (ammessi: {', '.join(STATI_PS)})")
    if not isinstance(operatore_ps, str) or not operatore_ps.strip() or len(operatore_ps) > 60:
        p.append("operatore_ps: stringa 1-60 caratteri")
    if destinazione_alternativa is not None and (not isinstance(destinazione_alternativa, str) or len(destinazione_alternativa) > 80):
        p.append("destinazione_alternativa: stringa ≤80 caratteri")
    if stato == "dirotta" and not (destinazione_alternativa or "").strip():
        p.append("stato=dirotta richiede destinazione_alternativa")
    return p


# ── 6c. Triage START per incidente maggiore (colori) ─────────────────────────────────────
TRIAGE_START = ("rosso", "giallo", "verde", "nero")

# ── 7. Incidenti maggiori (più pazienti) ─────────────────────────────────────────────────
def riepilogo_incidente(incidente: Dict, board: List[Dict]) -> Dict:
    pre = [r for r in board if r.get("incidente_id") == incidente["id"]]
    conte: Dict[str, int] = {}
    start: Dict[str, int] = {}
    for r in pre:
        p = (r.get("prealert") or {}).get("priorita", "SCADUTO")
        conte[p] = conte.get(p, 0) + 1
        if r.get("triage_start"):
            start[r["triage_start"]] = start.get(r["triage_start"], 0) + 1
    return {**incidente, "pazienti": len(pre), "per_priorita": conte, "per_triage_start": start,
            "pre_alert": [{"id": r["id"], "priorita": (r.get("prealert") or {}).get("priorita"),
                           "tipi": (r.get("tipo_paziente") or {}).get("tipi"), "triage_start": r.get("triage_start"),
                           "eta_arrivo_min": r.get("eta_corrente", (r.get("prealert") or {}).get("eta_arrivo_stimato_min"))} for r in pre]}


# ── banco che SA FALLIRE ────────────────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    stemi = {"priorita": "ALTO", "cardio": True, "percorsi_attivare": ["STEMI: cath lab"], "trauma_team": False,
             "criteri_prealert_2025": {"condizioni_specifiche": [{"condizione": "stemi"}]}}
    gen = {"priorita": "BASSO", "percorsi_attivare": [], "criteri_prealert_2025": {"condizioni_specifiche": []}}
    ped = {"priorita": "NON_VALUTABILE_PEDIATRICO", "percorsi_attivare": []}
    t1, t2, t3 = classifica_tipo(stemi), classifica_tipo(gen), classifica_tipo(ped)
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 10
    ok = bool(t1["team_da_allertare"] == ["cath_lab"] and t2["tipi"] == ["generale"] and t3["tipi"][0] == "pediatrico"
          and not valida_posizione(45.4, 9.2, 12) and valida_posizione(95, 9.2, 12) and valida_posizione(None, 9.2, 12)
          and not valida_messaggio("ps", "dr", "ok") and valida_messaggio("medico", "dr", "ok")
          and not valida_allegato("ecg", "image/png", png) and valida_allegato("ecg", "image/png", b"GIF89a")
          and valida_allegato("ecg", "image/gif", png) and valida_allegato("ecg", "image/png", b"\x89PNG\r\n\x1a\n" + b"0" * MAX_ALLEGATO)
          and not valida_esito("dr", "percorso_confermato", True, 35) and valida_esito("dr", "guarito", None, None))
    b = [{"id": 1, "ts": "2026-09-13T10:00:00+00:00", "prealert": {"priorita": "ALTO", "criteri_prealert_2025": {"pre_alert_indicato": True}},
          "ricezioni": [{"latenza_s": 40, "risposta_alternativa": True}],
          "esiti": [{"esito": "percorso_confermato"}, {"esito": "percorso_non_necessario"}]},   # conta solo l'ULTIMO
         {"id": 2, "ts": "2026-09-13T10:00:00+00:00", "prealert": {"priorita": "BASSO", "criteri_prealert_2025": {"pre_alert_indicato": False}},
          "ricezioni": [], "esiti": [{"esito": "percorso_confermato", "tempo_porta_intervento_min": 20}]}]
    m = metriche(b)
    ok = (ok and m["over_triage_proxy"] == 1 and m["under_triage_proxy"] == 1 and m["quota_risposte_alternative"] == 1.0
          and m["percorsi_confermati"] == 1 and [x["id"] for x in m["da_escalare"]] == [2]
          and not valida_stato_ps("saturo", "dr", None) and valida_stato_ps("dirotta", "dr", None)
          and bool(valida_stato_ps("chiuso", "dr", None)))
    return {"banco_sa_fallire": ok, "tipi": t1["team_da_allertare"], "metriche": {k: m[k] for k in ("over_triage_proxy", "under_triage_proxy")}}


if __name__ == "__main__":
    import json
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
