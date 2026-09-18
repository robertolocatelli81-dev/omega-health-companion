#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — app di COMUNICAZIONE TEAM (ambulanza ↔ pronto soccorso), REALE.

Web-app self-hosted (stdlib, zero dipendenze). L'ambulanza manda i DATI GREZZI
(vitali + farmaci + clinica); il SERVER calcola il pre-alert (unica fonte di
verità: ambulanza_intelligente.valuta_paziente, con gate pediatrico e
validazione vitali fail-closed), lo pubblica in bacheca, lo ancora al ledger
(SOLO digest — privacy by default) e lo espone in FHIR R4 e ATMIST.

Endpoints (tutti autenticati salvo la bacheca su loopback):
  GET  /                → bacheca PS (auto-refresh)
  POST /valuta          → {vitali, farmaci, eta, eta_arrivo_min, fast_segni?, clinica?}
                          → il server calcola, pubblica e ancora (digest)
  POST /prealert        → pre-alert PRE-calcolato (retro-compat; validato: deve
                          avere priorita e percorsi_attivare)
  POST /conferma        → {"id":.., "nota":".."} — il team conferma un percorso
  GET  /api/board       → lista pre-alert (JSON)
  GET  /fhir/<id>       → Bundle FHIR R4 del pre-alert (0 errori strutturali su HAPI e validator.fhir.org, 11/09/2026)
  GET  /atmist/<id>     → testo di consegna ATMIST

AUTENTICAZIONE (fix 2026-09-06 — prima il server era aperto): header
`X-Omega-Token` obbligatorio per ogni POST e per /api/, /fhir/, /atmist/.
Il token vive in `team_token.txt` (0600, generato al primo avvio). La bacheca
HTML resta leggibile senza token SOLO da loopback (il monitor del PS).

ONESTO: non è ancora un dispositivo medico né un sistema certificato; TLS va
messo davanti (reverse proxy o stunnel) quando esce da localhost; i dati della
bacheca sono IN MEMORIA (effimeri — coerente con la promessa privacy), solo i
DIGEST vanno sul ledger.
"""
from __future__ import annotations
import html
import json
import os
import socket
from typing import Optional
import secrets
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import ambulanza_intelligente as A
import audit_bridge as AB
import bacheca_store as BS
import chems_receipt as CR
import operatori as OP
import verbale_probatorio as VP
import coordinamento as CO
import fhir_export as FX
import scores_emergenza as S

_HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(_HERE, "team_token.txt")
VERBALI_DIR = os.path.join(_HERE, "verbali")          # verbali probatori marcati (digest-only)
MAX_BODY = 64 * 1024          # un pre-alert è piccolo: payload enormi = rifiuto
BOARD: list = []
_LOCK = threading.Lock()
ALLEGATI: dict = {}          # (id, n) -> bytes, SOLO in memoria, scadono con la bacheca
STATO_PS: dict = {"stato": "accetta", "ts": None, "operatore_ps": None}   # divert/capacità, a vocabolario chiuso
INCIDENTI: list = []         # incidenti maggiori (più pazienti)
_INCIDENTE_SEQ = [0]         # contatore MONOTONO (council 13/09: len()+1 dopo la scadenza collideva)
CAP = {"allegati": 10, "messaggi": 200, "posizioni": 100000, "esiti": 20, "ricezioni": 20, "incidenti": 500, "triage": 20, "conferme": 50}
_STORE: list = [None]        # journal cifrato OPT-IN (OMEGA_BOARD_STORE, 0.7.0): None = bacheca solo in RAM come sempre
_BOARD_SEQ = [0]             # id MONOTONO dei pre-alert (i record oltre 2×TTL vengono rimossi: len()+1 collideva)   # posizioni: taglio a 200 dopo append   # tetti per record (RAM)


def _nuovo_token() -> str:
    """Token casuale (256 bit) che NON inizia con '-': `--token <tok>` in una CLI lo leggerebbe come opzione
    (banco 18/09: `token_urlsafe` produce '-' iniziale circa 1 volta su 64)."""
    while True:
        t = secrets.token_urlsafe(32)
        if not t.startswith("-"):
            return t


def _token() -> str:
    if not os.path.exists(TOKEN_FILE):
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(_nuovo_token())
    if os.stat(TOKEN_FILE).st_mode & 0o077:                 # un token leggibile da altri non è un segreto: rifiuto nominato
        raise PermissionError(f"{TOKEN_FILE}: permessi troppo larghi ({oct(os.stat(TOKEN_FILE).st_mode & 0o777)}); attesi 0600")
    with open(TOKEN_FILE) as f:
        return f.read().strip()


BOARD_TTL_H = float(os.environ.get("OMEGA_BOARD_TTL_H", "24"))

# ── Profilo d'uso (0.7.0, INTENDED_USE.md) ─────────────────────────────────────────────────────────────────────
# "comunicazione" (DEFAULT dal 0.7.2, decisione dell'autore 18/09 dopo il giudizio Gemini Pro): il server NON esegue il motore
#   dei punteggi — solo vitali come inviati, tempi, identità, evidenza firmata. I campi non calcolati sono ELENCATI.
# "punteggi": il server calcola NEWS2/qSOFA/BE-FAST/criteri 2025 dai vitali (supporto informativo, decisione del medico).
#   Esposizione regolatoria dichiarata: EU MDR regola 11 / CH MepV. Chi lo vuole lo chiede PER ISCRITTO: OMEGA_PROFILO=punteggi,
#   così l'attivazione di un supporto decisionale non certificato è un atto esplicito dell'organizzazione, mai un default.
PROFILO_ENV = "OMEGA_PROFILO"
PROFILI = ("comunicazione", "punteggi")
CAMPI_DECISIONALI = ("NEWS2", "qSOFA", "BE_FAST", "priorita", "azione_raccomandata", "percorsi_attivare", "criteri_prealert_2025",
                     "sepsi_jrcalc", "cardio", "trauma_team", "flag_farmacologico", "interazioni_note", "arresto", "arresto_respiratorio",
                     "avvisi")      # anche gli avvisi: sono raccomandazioni calcolate (review Opus 18/09: «NON somministrare NITRATI»)


def profilo() -> str:
    p = os.environ.get(PROFILO_ENV, "comunicazione")
    if p not in PROFILI:
        raise SystemExit(f"{PROFILO_ENV}={p!r} non ammesso: {' | '.join(PROFILI)}")
    return p


def prealert_comunicazione(body: dict) -> dict:
    """Profilo 'comunicazione': il motore dei punteggi NON viene eseguito (review Gemini 18/09: mascherare l'output
    non basta, il trattamento deve limitarsi a conservazione e comunicazione). Qui si VALIDA soltanto: tipi stretti
    sui vitali (barella_prealert.valida_vitali), età, ETA, farmaci come lista di stringhe. Nessuna soglia, nessun
    punteggio, nessuna raccomandazione. Solleva ValueError con il problema nominato."""
    import barella_prealert as B
    vit = body.get("vitali")
    problemi = B.valida_vitali(vit)
    eta, eta_mesi, arrivo = body.get("eta"), body.get("eta_mesi"), body.get("eta_arrivo_min", 0)
    # stessi limiti del motore (ambulanza_intelligente.valuta_paziente): un client di 0.7.1 che manda eta 67.0 o 90 farmaci
    # non deve vedere un 400 nuovo solo perché il default è cambiato (review Opus 18/09 r2)
    def _num(x):
        return not isinstance(x, bool) and isinstance(x, (int, float)) and x == x
    if eta is not None and not (_num(eta) and 0 <= eta <= 130):
        problemi.append(f"eta non valida: {eta!r} (atteso numero fra 0 e 130)")
    if eta_mesi is not None and not (_num(eta_mesi) and 0 <= eta_mesi <= 11):
        problemi.append(f"eta_mesi non valida: {eta_mesi!r} (atteso numero 0-11, solo sotto l'anno)")
    elif eta_mesi is not None and _num(eta) and eta >= 1:
        problemi.append(f"eta_mesi={eta_mesi!r} incoerente con eta={eta!r} (i mesi valgono solo sotto l'anno)")
    if eta is None and eta_mesi is None:
        problemi.append("eta o eta_mesi richiesta")
    if not (_num(arrivo) and 0 <= arrivo <= 600):
        problemi.append(f"eta_arrivo_min non valido: {arrivo!r} (atteso numero 0-600 minuti)")
    farmaci = body.get("farmaci") or []
    if not isinstance(farmaci, list) or not all(isinstance(f, str) for f in farmaci):
        problemi.append("farmaci deve essere una lista di stringhe")
    elif len(farmaci) > 100 or any(len(f) > 120 for f in farmaci):
        problemi.append("farmaci: lista troppo lunga o voce troppo lunga (max 100 voci, 120 caratteri)")
    if problemi:
        raise ValueError("; ".join(problemi))
    # input clinici del motore (segni FAST, condizioni, sepsi, clinica) che qui NON vengono né valutati né mostrati: dichiarati,
    # non scartati in silenzio (review Opus 18/09 r2)
    ignorati = [k for k in ("clinica", "fast_segni", "condizioni", "sepsi") if k in body]
    return {"vitali": dict(vit), "eta_paziente": eta, "eta_mesi": eta_mesi, "eta_arrivo_stimato_min": arrivo,
            "farmaci_in_uso": [f.strip() for f in farmaci if isinstance(f, str)], "avvisi": [],
            "profilo": "comunicazione", "campi_non_calcolati": list(CAMPI_DECISIONALI) + ["tipo_paziente"],
            "campi_ignorati": ignorati,
            "nota_profilo": "profilo comunicazione: motore dei punteggi NON eseguito; vitali come inviati; la valutazione è del clinico"}


def applica_profilo(prealert: dict) -> dict:
    """Profilo 'comunicazione': toglie ogni campo decisionale dal pre-alert e lo DICHIARA; 'punteggi': invariato."""
    if profilo() != "comunicazione" or prealert.get("profilo") == "comunicazione":   # già in profilo: intatto (review Opus r2)
        return prealert
    tolti = [k for k in CAMPI_DECISIONALI if k in prealert]
    out = {k: v for k, v in prealert.items() if k not in CAMPI_DECISIONALI}
    out["avvisi"] = []                                  # il campo resta (la pagina lo legge), vuoto
    out["profilo"] = "comunicazione"
    out["campi_non_calcolati"] = tolti + ["tipo_paziente"]
    out["nota_profilo"] = "profilo comunicazione: nessun punteggio né raccomandazione calcolati; vitali come inviati; la valutazione è del clinico"
    return out


_STORE_ERR: list = [None]      # ultimo errore del journal, nominato in OGNI risposta JSON (campo journal_error / header X-Omega-Journal-Error)
_STORE_ERR_N: list = [0]       # conteggio cumulativo: non si azzera al successo successivo (review Opus r2)


def _journal(op, *a) -> bool:
    """Esegue un'operazione sul journal; un errore del disco/sqlite NON fa cadere la richiesta (il record è già firmato
    e in bacheca): viene memorizzato e dichiarato (review Opus 18/09)."""
    if _STORE[0] is None:
        return True
    try:
        op(*a); return True
    except Exception as e:  # noqa: BLE001 — sqlite3.Error, OSError, InvalidTag
        _STORE_ERR[0] = f"{type(e).__name__}: {str(e)[:120]}"; _STORE_ERR_N[0] += 1
        return False


def _persisti_record(r: dict) -> bool:
    """Journal cifrato opt-in: salva SOLO i campi ammessi (bacheca_store.CAMPI_RECORD); no-op senza store."""
    return _journal(lambda: _STORE[0].salva_record(r))


def _persisti_incidente(i: dict) -> bool:
    return _journal(lambda: _STORE[0].salva_incidente(i))


def _ripristina_da_store() -> dict:
    """All'avvio con OMEGA_BOARD_STORE: ricarica bacheca/incidenti/stato PS dal journal, poi applica il TTL
    (un record scaduto NON torna con i vitali) e riallinea i contatori. Ritorna un riepilogo dichiarato."""
    try:
        st = BS.apri_da_ambiente()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — chiave con permessi larghi / lunghezza errata: nominato all'avvio (review Opus r2)
        raise SystemExit(f"{BS.STORE_ENV}: journal non apribile ({type(e).__name__}: {e})")
    _STORE[0] = st
    if st is None:
        return {"store": None}
    try:
        snap = st.ripristina()
    except Exception as e:  # noqa: BLE001 — InvalidTag / sqlite corrotto: nominato, non un traceback (review Opus 18/09)
        raise SystemExit(f"{BS.STORE_ENV}: journal non decifrabile o corrotto ({type(e).__name__}): chiave diversa o file manomesso; "
                         "il ledger firmato resta intatto — rimuovere il journal per ripartire")
    with _LOCK:
        def _al_profilo(r):                        # il profilo VIVO governa ciò che si serve, non quello attivo quando il record
            if profilo() != "comunicazione":       # fu scritto (review Sonnet 18/09); anche tipo_paziente (banco 18/09)
                return r
            return {**r, "prealert": (applica_profilo(r["prealert"]) if isinstance(r.get("prealert"), dict) else r.get("prealert")),
                    "tipo_paziente": None}
        BOARD[:] = [_al_profilo(r) for r in snap["board"]]
        INCIDENTI[:] = snap["incidenti"]
        if snap["stato_ps"]:
            sp = snap["stato_ps"]
            try:
                vecchio = (datetime.now(timezone.utc) - datetime.fromisoformat(sp.get("ts"))).total_seconds() / 3600 > BOARD_TTL_H
            except (TypeError, ValueError):
                vecchio = True
            if vecchio:                                        # uno stato più vecchio del TTL non è attuale: si riparte da «accetta»
                STATO_PS.update({"stato": "accetta", "ts": None, "operatore_ps": None, "destinazione_alternativa": None,
                                 "ripristinato_senza": (sp.get("ripristinato_senza") or []) + ["stato (più vecchio del TTL: riportato ad accetta)"]})
            elif sp.get("stato") == "dirotta":                 # la destinazione non è mai su disco: «dirotta» torna come «saturo», la direzione
                STATO_PS.update({"stato": "saturo", "ts": sp.get("ts"), "operatore_ps": sp.get("operatore_ps"), "destinazione_alternativa": None,   # PRUDENTE (review Opus r2)
                                 "ripristinato_senza": (sp.get("ripristinato_senza") or []) + ["stato dirotta senza destinazione: riportato a saturo, va riconfermato"]})
            else:
                STATO_PS.update({k: v for k, v in sp.items() if k in ("stato", "ts", "operatore_ps", "destinazione_alternativa", "ripristinato_senza")})
        _BOARD_SEQ[0] = max([_BOARD_SEQ[0], AB.ultimo_id_prealert()] + [int(r["id"]) for r in BOARD])
        _INCIDENTE_SEQ[0] = max([_INCIDENTE_SEQ[0], AB.ultimo_id("incidente")] + [int(i["id"]) for i in INCIDENTI])
        scaduti = _scadenza_bacheca()
    return {"store": st.path, "record": len(BOARD), "incidenti": len(INCIDENTI), "scaduti_al_ripristino": scaduti,
            "scartati_senza_ts": snap.get("scartati_senza_ts", 0),
            "non_ripristinati": list(BS.NON_PERSISTITI) + ["descrizione incidente"]}


def _scadenza_bacheca(now: Optional[datetime] = None) -> int:
    """Svuota i dati clinici dei record scaduti (chiamare sotto _LOCK). Ritorna quanti ha svuotato."""
    now = now or datetime.now(timezone.utc)
    n = 0
    for r in BOARD:
        if r.get("vitali") is None and r.get("prealert") is None:
            # già scaduto: tenerlo VUOTO (ciò che fosse entrato dopo la scadenza non deve restare in RAM)
            r["messaggi"], r["posizioni"], r["allegati"], r["esiti"], r["ricezioni"] = [], [], [], [], []
            r["conferme"], r["triage"], r["triage_start"], r["tipo_paziente"] = [], [], None, None   # council 15/09: erano dimenticati
            for k in [k for k in ALLEGATI if k[0] == r["id"]]:
                ALLEGATI.pop(k, None)
            continue
        try:
            eta_h = (now - datetime.fromisoformat(r["ts"])).total_seconds() / 3600
        except (KeyError, ValueError):
            continue
        if eta_h > BOARD_TTL_H:
            r["vitali"] = None
            r["prealert"] = None
            r["scaduto"] = True
            r["messaggi"] = []
            r["posizioni"] = []
            r["esiti"] = []            # esito clinico + operatore: fuori dalla RAM alla scadenza (il ledger firmato resta, a digest)
            r["ricezioni"] = []
            r["conferme"], r["triage"], r["triage_start"], r["tipo_paziente"] = [], [], None, None   # nota clinica e categoria: fuori dalla RAM
            for k in [k for k in ALLEGATI if k[0] == r["id"]]:
                ALLEGATI.pop(k, None)
            r["allegati"] = []
            _persisti_record(r)                    # DOPO lo svuotamento: il journal dimentica esiti/ricezioni/triage come la RAM (review 18/09)
            n += 1
    # crescita illimitata (council 15/09): i record scaduti da oltre max(2×TTL, 24 h) escono del tutto dalla
    # bacheca (un record svuotato resta consultabile — 410, vuoto — per almeno un giorno)
    for r in [r for r in BOARD if r.get("scaduto")]:
        try:
            if (now - datetime.fromisoformat(r["ts"])).total_seconds() / 3600 > max(2 * BOARD_TTL_H, 24):
                BOARD.remove(r)
                _journal(lambda: _STORE[0].dimentica_record(r["id"]))
        except (KeyError, ValueError):
            pass
    # incidenti: la lista non cresceva mai (council 13/09) → oltre 2×TTL dall'apertura spariscono
    for i in [i for i in INCIDENTI if (now - datetime.fromisoformat(i["ts"])).total_seconds() / 3600 > 2 * BOARD_TTL_H]:
        INCIDENTI.remove(i)
        _journal(lambda: _STORE[0].dimentica_incidente(i["id"]))
    return n


def _pubblica(prealert: dict, vitali: dict | None,
              operatore: str = "equipaggio-ambulanza", incidente_id: int | None = None, identita: str = "dichiarata") -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    prov = S.ancora_prealert(prealert, ts)          # digest-only di default
    with _LOCK:
        if _BOARD_SEQ[0] == 0:            # after a restart continue from the signed ledger (council r2: ids were reused)
            _BOARD_SEQ[0] = AB.ultimo_id_prealert()
        rid = _BOARD_SEQ[0] + 1                # l'id si CONSUMA solo dopo la firma (review r2: prima una firma fallita
                                               # bruciava l'id e lasciava un buco nel trail)
        # audit: CREATE firmato authorship (motore Part 11 se presente, altrimenti firma locale Ed25519); senza
        # firma alza FirmaNonDisponibile (fail-closed 0.6.1) salvo opt-in esplicito OMEGA_HEALTH_ALLOW_UNSIGNED=1
        audit = AB.registra_prealert(f"prealert-{rid}",
                                     S._hash(prealert), operatore, identita=identita)   # l'identità entra nel record FIRMATO (review Opus r2)
        _BOARD_SEQ[0] = rid
        rec = {"id": rid, "ts": ts, "prealert": prealert,
               "vitali": vitali, "provenienza": prov,
               "audit": audit, "conferme": [], "ricezioni": [], "messaggi": [], "posizioni": [],
               "allegati": [], "esiti": [], "incidente_id": incidente_id,
               "tipo_paziente": (None if prealert.get("profilo") == "comunicazione" else CO.classifica_tipo(prealert))}
        # ^ comunicazione: nemmeno il tipo paziente/team da allertare è calcolato (review Opus 18/09); è dichiarato in campi_non_calcolati
        BOARD.append(rec)
        _persisti_record(rec)
        # Ritenzione in memoria (FIX 2026-09-11): la bacheca è effimera per DESIGN, ma senza scadenza i
        # vitali restavano in RAM finché viveva il processo. I record più vecchi di BOARD_TTL_H ore
        # perdono vitali e pre-alert (restano id/ts/provenienza = digest) — il ledger è già digest-only.
        _scadenza_bacheca()
    return rec


_COL = {"ALTO": "#c0392b", "MEDIO": "#e67e22", "BASSO": "#27ae60",
        "NON_VALUTABILE_PEDIATRICO": "#8e44ad", "NON_VALUTABILE_DATI_INVALIDI": "#7f8c8d",
        "SCADUTO": "#bbb"}


def _pagina() -> str:
    with _LOCK:
        _scadenza_bacheca()            # round 3: la scadenza vale a ogni LETTURA, non solo alla pubblicazione
        board = list(BOARD)
    righe = []
    for r in reversed(board):
        pa = r["prealert"] or {"priorita": "SCADUTO", "profilo": profilo(), "azione_raccomandata":
                               f"dati clinici rimossi dalla bacheca dopo {BOARD_TTL_H:g} h (ritenzione)"}
        pr = pa.get("priorita", "—")
        perc = "".join(f"<li>{html.escape(p)}</li>" for p in pa.get("percorsi_attivare", [])) or "<li>—</li>"
        avv = "".join(f"<li class=warn>{html.escape(a)}</li>" for a in pa.get("avvisi", []))
        conf = "".join(
            f"<span class=ok>✓ {html.escape(c['nota'])} — {html.escape(c['operatore'])}"
            f"{' 🖋' if c.get('audit', {}).get('livello') == 'part11' else ''}</span> "
            for c in r["conferme"]) or "<i>nessuna conferma</i>"
        sha = (r["provenienza"].get("self_hash") or "")[:16]
        righe.append(f"""
        <div class=card style="border-left:8px solid {_COL.get(pr,'#777')}">
          <div class=hdr><b>#{r['id']}</b> · <span class=pri style="background:{_COL.get(pr,'#777')}">{html.escape(str(pr))}</span>
             · {("dati clinici rimossi" if pa.get('priorita') == 'SCADUTO' else ("vitali come inviati: " + html.escape(", ".join(f"{k} {v}" for k, v in (pa.get('vitali') or {}).items()))) if pa.get('profilo') == 'comunicazione' else ("NEWS2 " + html.escape(str(pa.get('NEWS2','—')))))} · arrivo {html.escape(str(pa.get('eta_arrivo_stimato_min','?')))} min</div>
          <div class=az>{html.escape(str(pa.get('nota_profilo') if pa.get('profilo') == 'comunicazione' else pa.get('azione_raccomandata','')))}</div>
          <ul>{perc}{avv}</ul>
          <div class=meta>conferme: {conf} · <a href="/fhir/{r['id']}">FHIR</a> · <a href="/atmist/{r['id']}">ATMIST</a></div>
          <form method=post action=/conferma>
            <input type=hidden name=id value="{r['id']}">
            __TOKEN_FIELD__
            <input name=operatore placeholder="nome operatore (firma)">
            <input name=nota placeholder="conferma percorso (es. stroke team pronto)">
            <button>Conferma</button>
          </form>
          <div class=sha>🔒 provenienza (digest nel ledger) {sha}…</div>
        </div>""")
    return f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>
<title>OMEGA · Bacheca Pronto Soccorso</title>
<style>body{{font-family:system-ui;margin:0;background:#0f1419;color:#e6e6e6}}
h1{{background:#16213e;margin:0;padding:14px 18px;font-size:18px}}
.card{{background:#1b2430;margin:12px 18px;padding:12px 16px;border-radius:8px}}
.pri{{color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold}}
.hdr{{font-size:15px;margin-bottom:6px}} .az{{color:#ffd479;font-size:13px}}
ul{{margin:6px 0}} li{{margin:2px 0}} .warn{{color:#ff9f43}}
.meta{{font-size:13px;color:#9aa}} .ok{{color:#27ae60}} .sha{{font-size:11px;color:#667;margin-top:6px}}
a{{color:#6cf}} input,button{{padding:6px;margin-top:6px}}
button{{background:#0f3460;color:#fff;border:0;border-radius:4px;cursor:pointer}}
</style><h1>🚑 OMEGA · Bacheca Pronto Soccorso — pre-alert in arrivo (auto-refresh 5s)</h1>
{''.join(righe) or '<div class=card>Nessun pre-alert attivo.</div>'}
<div style="margin:18px;font-size:11px;color:#667">software di supporto alla comunicazione —
NON un dispositivo medico; {_nota_piede()}; la decisione è del medico</div>"""


def _nota_piede() -> str:
    return ("profilo comunicazione: nessun punteggio calcolato, i vitali sono quelli inviati dall'equipaggio" if profilo() == "comunicazione"
            else "profilo punteggi (opt-in): gli score sono standard pubblicati, non certificati qui")


def _evento_su_record(rid: int, lista: str, azione: str, dettaglio: dict, operatore: str, elemento: dict):
    """Firma nel ledger e append in bacheca sotto LO STESSO lock, dopo il ricontrollo di scadenza e tetto
    (council 13/09 round 2: firmare prima del ricontrollo lasciava nel trail eventi che la bacheca scartava).
    Ritorna (codice_http, payload)."""
    with _LOCK:
        _scadenza_bacheca()
        r = next((x for x in BOARD if x["id"] == rid), None)
        if not r or r.get("prealert") is None:
            return 404, {"ok": False, "error": f"pre-alert {rid} inesistente o scaduto"}
        if len(r.setdefault(lista, [])) >= CAP[lista]:
            return 429, {"ok": False, "error": f"tetto raggiunto per {lista} ({CAP[lista]} per pre-alert)"}
        audit = AB.registra_evento_clinico(f"prealert-{rid}", azione, dettaglio, operatore)
        r[lista].append({**elemento, "audit": audit})
        _persisti_record(r)
        return 200, {"ok": True, "id": rid, "n": len(r[lista]), "audit": audit, "record": r}


def _find(rid: int):
    with _LOCK:
        _scadenza_bacheca()            # round 3: /fhir e /atmist serviranno 410 anche senza nuove POST
        for r in BOARD:
            if r["id"] == rid:
                return r
    return None


class OperatoreRichiesto(Exception):
    """Modalità pilota: l'evento clinico richiede un operatore autenticato, non un nome dichiarato."""


class NomeRiservato(Exception):
    """Il nome dichiarato nel body coincide con un operatore registrato: serve il SUO token."""


class RegistroNonLeggibile(Exception):
    """operatori.json con permessi troppo larghi: nessuna autenticazione finché non è sistemato."""


class H(BaseHTTPRequestHandler):
    timeout = 30            # Slowloris: un body dichiarato ma mai inviato libera il thread dopo 30 s (socket.timeout)
    server_version = "omega-team/1.0"

    def _read_body(self, n: int, deadline_s: Optional[float] = None):
        """Reads n bytes in chunks under a deadline proportional to the size (≥ 15 s, +1 s per 32 KiB: a 2 MiB ECG
        on a 256 kbps ambulance uplink is legitimate — council r2) and bounded per read by the remaining time
        (council 15/09, Gemini: the per-read socket timeout did not stop a body trickled for hours). None = late."""
        import time
        deadline_s = deadline_s if deadline_s is not None else max(15.0, n / 32768.0)
        t0, buf = time.monotonic(), bytearray()
        while len(buf) < n:
            remaining = deadline_s - (time.monotonic() - t0)
            if remaining <= 0:
                return None
            try:
                self.connection.settimeout(min(remaining, 30.0))
                chunk = self.rfile.read(min(65536, n - len(buf)))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        return self._send_bytes(code, body, ctype, extra)

    def _send_bytes(self, code, body: bytes, ctype, extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _senza_sale(o):
        """Il sale dei commitment HMAC vive SOLO in RAM: mai in una risposta API (review Opus r2), come mai nel journal."""
        if isinstance(o, dict):
            return {k: H._senza_sale(v) for k, v in o.items() if k != "sale"}
        if isinstance(o, list):
            return [H._senza_sale(x) for x in o]
        return o

    def _json(self, code, obj):
        obj = self._senza_sale(obj)
        if isinstance(obj, dict) and _STORE_ERR[0]:          # journal in errore: dichiarato in OGNI risposta JSON (review Opus/Sonnet r2)
            obj = {**obj, "journal_error": _STORE_ERR[0], "journal_errori_totali": _STORE_ERR_N[0]}
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8",
                   extra=({"X-Omega-Journal-Error": str(_STORE_ERR_N[0])} if _STORE_ERR[0] else None))

    def _authed(self, qs_token: str | None = None) -> bool:
        """Token di amministrazione (team_token.txt) OPPURE token di un operatore registrato (0.7.0). Con un token
        operatore l'identità autenticata è memorizzata in self._op e vince sul nome scritto nel body."""
        self._op = None
        op_tok = self.headers.get("X-Omega-Operatore-Token")
        if op_tok:                                   # il token operatore, se presente, DECIDE: valido → identità
            try:
                op = OP.autentica(op_tok)            # autenticata; non valido → 401, mai un declassamento silenzioso
            except PermissionError as e:             # registro con permessi larghi: nominato (review Opus 18/09), non un traceback
                raise RegistroNonLeggibile(str(e))
            if op:                                   # all'admin/dichiarato (banco su installazione pulita, 18/09)
                self._op = op
                return True
            return False
        tok = self.headers.get("X-Omega-Token") or qs_token
        if tok and secrets.compare_digest(tok.encode("utf-8", "replace"), _token().encode("utf-8")):   # byte: un token non-ASCII non alza TypeError
            return True
        try:
            op = OP.autentica(tok)                   # un token operatore passato nel campo generico vale lo stesso
        except PermissionError as e:
            raise RegistroNonLeggibile(str(e))
        if op:
            self._op = op
            return True
        return False

    def _operatore(self, body, default: str, campo: str = "operatore") -> str:
        """Nome dell'operatore per la FIRMA: quello autenticato se c'è un token operatore, altrimenti quello del body
        (dichiarato). In modalità pilota (OMEGA_REQUIRE_OPERATOR=1) il dichiarato non basta: solleva 403."""
        op = getattr(self, "_op", None)
        if op:
            return op["slug"]
        if OP.richiesto():
            raise OperatoreRichiesto()
        nome = str((body or {}).get(campo) or default).strip()[:60] or default
        if nome and (AB._slug(nome) in ("admin", "anonimo", "sistema") or not AB._slug(nome)):   # confronto sullo SLUG (chiave): «Admin»
            raise NomeRiservato(nome)                                                              # non aggira (review Opus r3)
        try:
            riservato = OP.esiste(nome)              # review Opus 18/09: un nome DICHIARATO uguale a uno slug registrato
        except PermissionError as e:                 # firmerebbe con la chiave di quell'operatore: rifiutato
            raise RegistroNonLeggibile(str(e))
        if riservato:
            raise NomeRiservato(nome)
        return nome

    def _identita(self) -> str:
        return "autenticata" if getattr(self, "_op", None) else "dichiarata"

    def _is_loopback(self) -> bool:
        """Loopback VERO: indirizzo locale E nessun header di inoltro. Dietro un reverse proxy (nginx, docker, ngrok) ogni
        richiesta esterna arriva da 127.0.0.1: senza questo controllo il token admin finiva nella pagina di chiunque
        (giudizio Gemini Pro 18/09)."""
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return False
        return not any(self.headers.get(h) for h in ("X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Forwarded-Host", "Via"))

    def do_GET(self):
        try:
            return self._do_GET()
        except RegistroNonLeggibile as e:
            return self._json(503, {"ok": False, "error": f"registro operatori non leggibile: {e}"})

    def _do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            if not (self._is_loopback() or self._authed()):
                return self._send(401, "token richiesto")
            # in modalità pilota il token admin NON viene messo nella pagina (creerebbe operatori): il form di conferma
            # chiede il token OPERATORE, digitato per richiesta (review Opus r2/r3)
            if OP.richiesto():
                campo = '<input name=token placeholder="token operatore" type=password>'
            else:
                campo = f'<input type=hidden name=token value="{_token() if self._is_loopback() else ""}">'
            return self._send(200, _pagina().replace("__TOKEN_FIELD__", campo))
        if not self._authed():
            return self._json(401, {"ok": False, "error": "X-Omega-Token mancante o errato"})
        if self.path == "/api/board":
            with _LOCK:
                _scadenza_bacheca()
                return self._json(200, BOARD)
        if self.path == "/audit":
            return self._json(200, AB.verifica_trail())
        if self.path == "/metriche":                       # QA/QI aggregate, senza PII
            with _LOCK:
                _scadenza_bacheca()
                return self._json(200, CO.metriche(list(BOARD)))
        if self.path == "/incidenti":
            with _LOCK:
                return self._json(200, [CO.riepilogo_incidente(i, list(BOARD)) for i in INCIDENTI])
        path_noq = self.path.split("?", 1)[0]          # la query (es. ?marca=1) non fa parte dell'id
        if path_noq.startswith("/allegato/"):
            try:
                rid, n = (int(x) for x in path_noq[len("/allegato/"):].split("/"))
            except ValueError:
                return self._json(400, {"ok": False, "error": "atteso /allegato/<id>/<n>"})
            with _LOCK:
                _scadenza_bacheca()
                raw = ALLEGATI.get((rid, n))
                r = next((x for x in BOARD if x["id"] == rid), None)
                meta = (r["allegati"][n - 1] if r and raw is not None and 0 < n <= len(r["allegati"]) else None)
            if raw is None or meta is None:
                return self._json(404, {"ok": False, "error": "allegato inesistente o scaduto"})
            # mai reso inline nella stessa origine della bacheca (council 13/09: un XHTML come text/xml
            # eseguirebbe script nel browser del PS): download + nosniff + CSP sandbox
            return self._send(200, raw, meta["content_type"], extra={
                "Content-Disposition": f'attachment; filename="prealert-{rid}-{n}"',
                "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"})
        if path_noq.startswith("/incidente/"):
            try:
                iid = int(path_noq[len("/incidente/"):])
            except ValueError:
                return self._json(400, {"ok": False, "error": "id non numerico"})
            with _LOCK:
                inc = next((i for i in INCIDENTI if i["id"] == iid), None)
                if not inc:
                    return self._json(404, {"ok": False, "error": "incidente inesistente"})
                return self._json(200, CO.riepilogo_incidente(inc, list(BOARD)))
        for prefix, fn in (("/fhir/", self._fhir), ("/atmist/", self._atmist), ("/verbale/", self._verbale),
                           ("/messaggi/", self._messaggi)):
            if path_noq.startswith(prefix):
                try:
                    rid = int(path_noq[len(prefix):])
                except ValueError:
                    return self._json(400, {"ok": False, "error": "id non numerico"})
                return fn(rid)
        return self._json(404, {"ok": False, "error": "not found"})

    def _fhir(self, rid: int):
        r = _find(rid)
        if not r:
            return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente"})
        if r.get("prealert") is None:
            return self._json(410, {"ok": False, "error": f"pre-alert {rid} scaduto: dati clinici rimossi dopo {BOARD_TTL_H:g} h"})
        b = FX.prealert_to_fhir(r["prealert"], r.get("vitali") or {}, r["ts"],
                                provenienza_omega=r.get("provenienza"))
        return self._send(200, json.dumps(b, ensure_ascii=False), "application/fhir+json; charset=utf-8")

    def _verbale(self, rid: int):
        # Verbale probatorio digest-only del pre-alert (2026-09-13): eventi firmati ri-verificati,
        # cronologia, digest. Marca RFC 3161 SOLO su richiesta esplicita (?marca=1) e solo se
        # HEALTH_TSA_URL è configurata: nessuna chiamata di rete implicita.
        r = _find(rid)
        if not r:
            return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente"})
        v = VP.verbale(f"prealert-{rid}")
        if parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").get("marca") == ["1"]:   # parsed, not substring
            tsa = os.environ.get("HEALTH_TSA_URL", "")
            if not tsa:
                v["marca_temporale"] = {"anchored": False, "note": "HEALTH_TSA_URL non configurata"}
            else:
                m = VP.marca_temporale_rfc3161(v["digest_verbale_sha256"], tsa)
                if m.get("anchored"):
                    m["verifica"] = VP.verifica_marca(m["tsr_b64"], v["digest_verbale_sha256"],
                                                      cafile=os.environ.get("HEALTH_TSA_CAFILE"))
                v["marca_temporale"] = m
                # i BYTE marcati vanno conservati (council 13/09): senza, la prova è su un digest che
                # nessuno custodisce. Solo digest/metadati: nessun dato sanitario nel file.
                v["persistito"] = VP.persisti_verbale(v, os.environ.get("HEALTH_VERBALI_DIR") or VERBALI_DIR)
        return self._send(200, json.dumps(v, ensure_ascii=False), "application/json; charset=utf-8")

    def _messaggi(self, rid: int):
        r = _find(rid)
        if not r:
            return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente"})
        with _LOCK:
            return self._json(200, {"id": rid, "messaggi": list(r.get("messaggi") or []),
                                    "eta_corrente_min": r.get("eta_corrente"), "triage_start": r.get("triage_start"),
                                    "stato_ps": STATO_PS,
                                    "posizioni": list(r.get("posizioni") or [])[-20:],
                                    "allegati": list(r.get("allegati") or []), "esiti": list(r.get("esiti") or [])})

    def _atmist(self, rid: int):
        r = _find(rid)
        if not r:
            return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente"})
        if r.get("prealert") is None:
            return self._json(410, {"ok": False, "error": f"pre-alert {rid} scaduto: dati clinici rimossi dopo {BOARD_TTL_H:g} h"})
        at = FX.atmist(r["prealert"].get("eta_paziente"), r["ts"][11:16],
                       "vedi pre-alert", ("vedi pre-alert" if r["prealert"].get("profilo") == "comunicazione" else "vedi percorsi"),
                       r["prealert"], trattamenti=[])      # nessun «vedi percorsi» dove i percorsi non esistono (review Opus r2)
        return self._send(200, at["testo_consegna"], "text/plain; charset=utf-8")

    def do_POST(self):
        try:
            return self._do_POST()
        except RegistroNonLeggibile as e:
            return self._json(503, {"ok": False, "error": f"registro operatori non leggibile: {e}"})
        except NomeRiservato as e:               # 0.7.0: il nome di un operatore registrato non si dichiara, si autentica
            if AB._slug(str(e)) in ("admin", "anonimo", "sistema") or not AB._slug(str(e)):
                return self._json(403, {"ok": False, "error": f"'{e}': nome riservato al sistema, non dichiarabile"})
            return self._json(403, {"ok": False, "error": f"'{e}' è un operatore registrato: usa il suo token (X-Omega-Operatore-Token)"})
        except OperatoreRichiesto:               # 0.7.0, modalità pilota: nessun evento clinico a nome dichiarato
            return self._json(403, {"ok": False, "error": f"{OP.REQUIRE_ENV}=1: serve un token operatore (X-Omega-Operatore-Token), "
                                                          "il nome nel body non basta"})
        except AB.FirmaNonDisponibile as e:      # fail-closed (0.6.1): mai registrare non firmato in silenzio → 503 nominato
            return self._json(503, {"ok": False, "error": f"audit non firmabile: {e}"})
        except (ConnectionError, TimeoutError):  # socket del client caduto o lento: NON è un errore di audit (review r3)
            raise
        except OSError as e:                     # chiavi/ledger non scrivibili (disco pieno, cartella read-only): in ogni
            # route la firma precede la mutazione dello stato (verificato route per route il 18/09), quindi lo stato in
            # memoria non è stato toccato → 503 nominato invece di una connessione caduta senza status
            return self._json(503, {"ok": False, "error": f"audit non scrivibile: {e.__class__.__name__}"})

    def _do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._json(400, {"ok": False, "error": "Content-Length invalido"})
        if n < 0:
            return self._json(400, {"ok": False, "error": "Content-Length invalido"})
        if self.path.startswith("/allegato/"):
            return self.do_POST_allegato(n)          # binario: mai decodificato come testo
        if self.path in ("/chems/ingest", "/chems/verifica"):
            return self.do_POST_chems(n)             # 0.7.0: documento CH EMS di TERZI, byte esatti, limite proprio
        if n > MAX_BODY:
            return self._json(413, {"ok": False, "error": "payload troppo grande"})
        raw = self._read_body(n)
        if raw is None:
            return self._json(408, {"ok": False, "error": "body non ricevuto entro la scadenza"})
        raw = raw.decode(errors="replace")
        if self.path == "/conferma":       # form della bacheca: token nel body
            q = parse_qs(raw)
            if not self._authed(q.get("token", [None])[0]):
                return self._send(401, "token richiesto")
            try:
                rid = int(q.get("id", ["0"])[0])
            except ValueError:
                return self._send(400, "id non numerico")
            nota = q.get("nota", [""])[0][:100]
            try:
                operatore = self._operatore({"operatore": q.get("operatore", [""])[0]}, "team-ps")
            except (OperatoreRichiesto, NomeRiservato) as e:                          # form HTML: risposta leggibile, non JSON
                return self._send(403, f"conferma NON registrata: {e if isinstance(e, NomeRiservato) else 'serve un token operatore (modalità pilota)'}")
            if nota:
                # ricontrollo di scadenza e tetto SOTTO il lock, firma DOPO il ricontrollo (council 15/09: la conferma
                # era l'unica lista senza tetto, sopravviveva alla scadenza ed era firmata prima del ricontrollo);
                # una nota scartata è un ERRORE esplicito, mai un redirect muto (council r2)
                with _LOCK:
                    _scadenza_bacheca()
                    r = next((x for x in BOARD if x["id"] == rid), None)
                    if not r or r.get("prealert") is None:
                        return self._send(410, "pre-alert inesistente o scaduto: nota NON registrata")
                    if len(r.setdefault("conferme", [])) >= CAP["conferme"]:
                        return self._send(429, f"tetto conferme raggiunto ({CAP['conferme']}): nota NON registrata")
                    audit = AB.registra_conferma(f"prealert-{rid}", nota, operatore)
                    r["conferme"].append({"nota": nota, "operatore": operatore, "audit": audit})
            return self._send(303, "", extra={"Location": "/"})
        if not self._authed():
            return self._json(401, {"ok": False, "error": "X-Omega-Token mancante o errato"})
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError) as e:
            # RecursionError incluso (attacco 06/09: array annidato 5000 livelli
            # uccideva il thread handler invece di rispondere 400)
            categoria = "troppo annidato" if isinstance(e, RecursionError) else "non decodificabile"
            return self._json(400, {"ok": False, "error": f"JSON invalido: {categoria}"})
        if not isinstance(body, dict):
            return self._json(400, {"ok": False, "error": "il body deve essere un oggetto JSON"})
        if self.path == "/valuta":
            return self.do_POST_valuta(body)
        return self.do_POST_altri(body)

    def do_POST_valuta(self, body):
        if True:   # (indentazione conservata dal blocco originale)
            try:
                if profilo() == "comunicazione":
                    out = {"PRE_ALERT_INTEGRATO": prealert_comunicazione(body)}     # nessun motore di punteggio eseguito
                else:
                    out = A.valuta_paziente(
                    body["vitali"], body.get("farmaci") or [], body.get("eta"),
                    body.get("eta_arrivo_min", 0),           # validato dentro valuta_paziente (0-600)
                    fast_segni=body.get("fast_segni"), clinica=body.get("clinica"),
                    condizioni=body.get("condizioni"), eta_mesi=body.get("eta_mesi"),
                    sepsi=body.get("sepsi"))
            except ValueError as e:
                # messaggi NOSTRI (validazione nominata), mai il testo di un'eccezione interna
                return self._json(400, {"ok": False, "error": f"input invalido: {e}"})
            except (KeyError, TypeError, AttributeError):
                return self._json(400, {"ok": False, "error": "input invalido: struttura del payload non conforme"})
            except Exception:                                    # noqa: BLE001 — l'input arriva dalla rete
                return self._json(400, {"ok": False, "error": "input invalido"})
            ts_start = body.get("triage_start")
            if ts_start is not None and ts_start not in CO.TRIAGE_START:
                return self._json(400, {"ok": False, "error": f"triage_start non ammesso: {ts_start!r} (ammessi: {', '.join(CO.TRIAGE_START)})"})
            inc = body.get("incidente_id")
            if inc is not None:
                with _LOCK:
                    esiste = (not isinstance(inc, bool)) and isinstance(inc, int) and any(i["id"] == inc for i in INCIDENTI)
                if not esiste:
                    return self._json(400, {"ok": False, "error": f"incidente_id inesistente: {inc!r}"})
            rec = _pubblica(out["PRE_ALERT_INTEGRATO"], body.get("vitali"),
                            operatore=self._operatore(body, "equipaggio-ambulanza"), incidente_id=inc, identita=self._identita())
            if ts_start is not None:          # tag iniziale: firmato come ogni decisione clinica
                _op0 = self._operatore(body, "equipaggio-ambulanza")
                _evento_su_record(rec["id"], "triage", "triage_start", {"triage_start": ts_start}, _op0,
                                  {"triage_start": ts_start, "operatore": _op0})
                with _LOCK:
                    rec["triage_start"] = ts_start
                    _persisti_record(rec)
            with _LOCK:
                stato_ps = dict(STATO_PS)
            return self._json(200, {"ok": True, "id": rec["id"], "identita": self._identita(),
                                    **({"journal_error": _STORE_ERR[0]} if _STORE_ERR[0] else {}),
                                    "prealert": out["PRE_ALERT_INTEGRATO"],
                                    "tipo_paziente": rec["tipo_paziente"], "stato_ps": stato_ps,
                                    "provenienza": rec["provenienza"]})

    MAX_CHEMS = 2 * 1024 * 1024                  # un Einsatzprotokoll completo dell'IG pesa ~60 KiB; 2 MiB è largo

    def do_POST_chems(self, n: int):
        """Modulo per gli incumbent (0.7.0): un ePCR qualsiasi manda un documento CH EMS e riceve una RICEVUTA
        firmata (digest dei byte esatti ancorato nel ledger locale, catena, chiave dell'operatore) verificabile
        offline; /chems/verifica rifà la verifica su ricevuta + byte. Il documento NON viene conservato: passa in
        memoria, se ne tiene il digest e i campi non clinici (missione, stato, conteggi) nel ledger."""
        if not self._authed():
            return self._json(401, {"ok": False, "error": "X-Omega-Token mancante o errato"})
        if n > self.MAX_CHEMS:
            return self._json(413, {"ok": False, "error": f"documento troppo grande (max {self.MAX_CHEMS} byte)"})
        raw = self._read_body(n)
        if raw is None:
            return self._json(408, {"ok": False, "error": "body non ricevuto entro la scadenza"})
        if self.path == "/chems/ingest":
            operatore = self._operatore({"operatore": self.headers.get("X-Omega-Operatore")}, "epcr-esterno")
            if not CR.OPERATORE_RE.match(operatore):    # stesso charset che la verifica esige: mai una ricevuta poi rifiutata (review Opus 18/09)
                return self._json(422, {"ok": False, "error": "operatore: ammessi lettere, cifre, spazio e . _ @ - (max 60)"})
            try:
                doc = CR.I.leggi_documento(bytes(raw))          # regole di documento strette; il digest è dei BYTE
                ex = CR.I.estrai_vitali(doc)
            except ValueError as e:
                return self._json(422, {"ok": False, "error": f"documento rifiutato: {e}"})
            except Exception:                                    # noqa: BLE001 — input dalla rete
                return self._json(422, {"ok": False, "error": "documento rifiutato: non leggibile come CH EMS"})
            ric = CR.emetti_ricevuta(bytes(raw), operatore, identita=self._identita())
            if not ric.get("ok"):
                return self._json(503, {"ok": False, "error": ric.get("motivo")})
            return self._json(200, {"ok": True, "ricevuta": ric,
                                    "letto": {"profili": doc["profili"], "entries": sum(doc["per_tipo"].values()),
                                              "missione": ex["missione"], "stato_documento": ex["stato_documento"],
                                              "avvisi": doc["avvisi"]}})
        # /chems/verifica: {"ricevuta": {...}, "documento_b64": "..."}
        try:
            body = json.loads(raw.decode("utf-8"))
            ric = body["ricevuta"]; doc_bytes = __import__("base64").b64decode(body["documento_b64"], validate=True)
        except Exception:                                        # noqa: BLE001
            return self._json(400, {"ok": False, "error": "atteso JSON {ricevuta, documento_b64}"})
        return self._json(200, CR.verifica_ricevuta(ric, doc_bytes))

    def do_POST_allegato(self, n: int):
        """ECG / foto della scena / documento: byte in memoria (scadono con la bacheca), digest nel ledger
        firmato, nessuna interpretazione automatica. Come Pulsara/Twiage condividono immagini, ma verificabile."""
        if not self._authed():
            return self._json(401, {"ok": False, "error": "X-Omega-Token mancante o errato"})
        if n > CO.MAX_ALLEGATO:
            return self._json(413, {"ok": False, "error": f"allegato troppo grande (max {CO.MAX_ALLEGATO} byte)"})
        try:
            rid = int(self.path[len("/allegato/"):].split("?")[0])
        except ValueError:
            return self._json(400, {"ok": False, "error": "id non numerico"})
        raw = self._read_body(n)
        if raw is None:
            return self._json(408, {"ok": False, "error": "allegato non ricevuto entro la scadenza"})
        tipo = (self.headers.get("X-Omega-Tipo") or "").strip().lower()
        ct = self.headers.get("Content-Type") or ""
        operatore = self._operatore({"operatore": self.headers.get("X-Omega-Operatore")}, "equipaggio-ambulanza")
        problemi = CO.valida_allegato(tipo, ct, raw)
        if problemi:
            return self._json(400, {"ok": False, "error": "allegato rifiutato", "problemi": problemi})
        meta = CO.descrivi_allegato(tipo, ct, raw)
        with _LOCK:
            _scadenza_bacheca()
            r = next((x for x in BOARD if x["id"] == rid), None)
            if not r or r.get("prealert") is None:
                return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente o scaduto"})
            if len(r["allegati"]) >= CAP["allegati"]:
                return self._json(429, {"ok": False, "error": f"tetto raggiunto per allegati ({CAP['allegati']} per pre-alert)"})
            audit = AB.registra_evento_clinico(f"prealert-{rid}", "allegato",
                                               {k: meta[k] for k in ("tipo", "content_type", "bytes", "sha256")}, operatore)
            r["allegati"].append({**meta, "operatore": operatore, "audit": audit})
            n_all = len(r["allegati"])
            ALLEGATI[(rid, n_all)] = raw
        return self._json(200, {"ok": True, "id": rid, "n": n_all, "sha256": meta["sha256"], "audit": audit})

    def do_POST_altri(self, body):
        if self.path in ("/ricezione", "/stato_ps", "/esito") and OP.richiesto():
            # modalità pilota: gli atti del PS li compie un operatore col ruolo ps (o admin); il ruolo clinico della
            # ricezione (clinico_senior, medico, …) resta un dato dichiarato dal vocabolario del verbale (review Opus 18/09)
            op = getattr(self, "_op", None)
            if not op or op["ruolo"] not in ("ps", "admin"):
                return self._json(403, {"ok": False, "error": "in modalità pilota questo atto richiede un operatore con ruolo ps"})
        if self.path == "/incidente":
            desc = str(body.get("descrizione") or "")[:120].strip()
            operatore = self._operatore(body, "centrale")
            if not desc:
                return self._json(400, {"ok": False, "error": "descrizione richiesta (≤120 caratteri)"})
            with _LOCK:      # firma e stato sotto lo stesso lock, firma PRIMA dell'append (Opus review 18/09: prima
                             # l'incidente entrava in memoria e poi si firmava; se la firma falliva restava un incidente
                             # senza audit, visibile in bacheca e conteggiato nel tetto)
                if len(INCIDENTI) >= CAP["incidenti"]:
                    return self._json(429, {"ok": False, "error": "tetto incidenti aperti raggiunto"})
                if _INCIDENTE_SEQ[0] == 0:        # after a restart continue from the signed ledger (0.6.1, review r3:
                    _INCIDENTE_SEQ[0] = AB.ultimo_id("incidente")   # `incidente-1` was re-CREATEd in the trail)
                nuovo_id = _INCIDENTE_SEQ[0] + 1
                # nel ledger va il DIGEST della descrizione (luogo/targhe/nomi = testo libero), evento CREATE firmato
                audit = AB.registra_evento_clinico(f"incidente-{nuovo_id}", "apertura_incidente",
                                                   {"descrizione": CO.impronta_testo(desc)}, operatore)
                _INCIDENTE_SEQ[0] = nuovo_id
                inc = {"id": nuovo_id, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "descrizione": desc, "aperto_da": operatore}      # descrizione SOLO in memoria (RAM del processo,
                # per la durata dell'incidente; mai su disco: nel ledger entra solo la sua impronta)
                INCIDENTI.append(inc)
                _persisti_incidente(inc)
            return self._json(200, {"ok": True, "incidente": inc, "audit": audit})
        if self.path == "/triage":
            # tag START (rosso/giallo/verde/nero): decisione clinica → FIRMATA e ri-aggiornabile (il re-triage è la norma)
            try:
                rid = int(body.get("id"))
            except (TypeError, ValueError):
                return self._json(400, {"ok": False, "error": "id non numerico"})
            tag = body.get("triage_start")
            if tag not in CO.TRIAGE_START:
                return self._json(400, {"ok": False, "error": f"triage_start non ammesso: {tag!r} (ammessi: {', '.join(CO.TRIAGE_START)})"})
            op = self._operatore(body, "equipaggio-ambulanza")
            code, out = _evento_su_record(rid, "triage", "triage_start", {"triage_start": tag}, op, {"triage_start": tag, "operatore": op})
            if code == 200:
                with _LOCK:
                    out["record"]["triage_start"] = tag
                    _persisti_record(out["record"])
                out = {k: v for k, v in out.items() if k != "record"}
            return self._json(code, out)
        if self.path == "/stato_ps":
            # divert / capacità (colonna portante di Pulsara/Twiage): il PS dichiara se accetta, è saturo o dirotta
            stato, op, dest = body.get("stato"), self._operatore(body, "", "operatore_ps"), body.get("destinazione_alternativa")
            problemi = CO.valida_stato_ps(stato, op, dest)
            if problemi:
                return self._json(400, {"ok": False, "error": "stato rifiutato", "problemi": problemi})
            dest = dest.strip() if isinstance(dest, str) else dest
            if not dest:
                dest = None                     # blanks are not a destination (council r2)
            imp, sale = (CO.impegno(dest) if dest else (None, None))
            det = {"stato": stato, "destinazione_alternativa": imp}
            with _LOCK:      # audit e stato sotto lo stesso lock: l'ordine nel ledger = l'ordine in memoria
                audit = AB.registra_evento_clinico("ps", "stato_ps", det, op)
                STATO_PS.pop("ripristinato_senza", None)     # un nuovo stato dichiarato sostituisce quello ripristinato (review Opus r2)
                STATO_PS.update({"stato": stato, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "operatore_ps": op, "destinazione_alternativa": dest, "sale": sale})
                _journal(lambda: _STORE[0].salva_stato_ps(STATO_PS))
            return self._json(200, {"ok": True, "stato_ps": {k: v for k, v in STATO_PS.items() if k != "sale"}, "audit": audit})
        if self.path in ("/posizione", "/messaggio", "/esito"):
            try:
                rid = int(body.get("id"))
            except (TypeError, ValueError):
                return self._json(400, {"ok": False, "error": "id non numerico"})
            ts_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if self.path == "/posizione":
                lat, lon, eta = body.get("lat"), body.get("lon"), body.get("eta_arrivo_min")
                problemi = CO.valida_posizione(lat, lon, eta)
                if problemi:
                    return self._json(400, {"ok": False, "error": "posizione rifiutata", "problemi": problemi})
                ev, sale = CO.evento_posizione(lat, lon, eta)    # nel ledger: ETA + IMPEGNO salato della posizione, mai coordinate
                code, out = _evento_su_record(rid, "posizioni", "aggiornamento_eta", ev,
                                              self._operatore(body, "equipaggio-ambulanza"),
                                              {"lat": lat, "lon": lon, "eta_arrivo_min": eta, "ts": ev["ts"], "sale": sale})
                if code == 200:
                    with _LOCK:
                        out["record"]["posizioni"] = out["record"]["posizioni"][-200:]
                        out["record"]["eta_corrente"] = eta   # il pre-alert ancorato NON si muta
                    out = {"ok": True, "id": rid, "eta_arrivo_min": eta, "audit": out["audit"]}
                return self._json(code, out)
            if self.path == "/messaggio":
                da, op, testo = body.get("da"), self._operatore(body, ""), body.get("testo")
                problemi = CO.valida_messaggio(da, op, testo)
                if problemi:
                    return self._json(400, {"ok": False, "error": "messaggio rifiutato", "problemi": problemi})
                imp, sale = CO.impegno(testo)
                code, out = _evento_su_record(rid, "messaggi", "messaggio", {"da": da, **imp}, op,
                                              {"da": da, "operatore": op, "testo": testo, "ts": ts_now, "hmac_sha256": imp["hmac_sha256"], "sale": sale})
                return self._json(code, {k: v for k, v in out.items() if k != "record"})
            # /esito — close the loop
            op = self._operatore(body, "", "operatore_ps")
            esito, diag, tempo = body.get("esito"), body.get("diagnosi_confermata"), body.get("tempo_porta_intervento_min")
            problemi = CO.valida_esito(op, esito, diag, tempo)
            if problemi:
                return self._json(400, {"ok": False, "error": "esito rifiutato", "problemi": problemi})
            nota = body.get("nota")
            imp, sale = (CO.impegno(str(nota)[:500]) if nota else (None, None))
            det = {"esito": esito, "diagnosi_confermata": diag,
                   "tempo_porta_intervento_min": (int(round(tempo)) if tempo is not None else None),   # interi nei record firmati
                   "nota": imp}
            code, out = _evento_su_record(rid, "esiti", "esito_clinico", det, op, {**det, "operatore_ps": op, "ts": ts_now, "sale": sale})
            if code == 200:
                out = {"ok": True, "id": rid, "esito": esito, "audit": out["audit"]}
            return self._json(code, out)
        if self.path == "/rimuovi-nota":
            # DICHIARATO alla DPGA (9B/9C): «the organisation can remove any note».
            # Disciplina Part 11: la rimozione è REGISTRATA con motivo e operatore
            # (audit trail), mai silenziosa; la nota sparisce dalla bacheca.
            try:
                rid = int(body["id"]); idx = int(body["indice_nota"])
                motivo = str(body["motivo"]).strip()
                operatore = self._operatore(body, "team-ps")
                if not motivo:
                    raise ValueError("motivo obbligatorio")
            except (KeyError, TypeError, ValueError) as e:
                return self._json(400, {"ok": False, "error": f"servono id, indice_nota, motivo: {e}"})
            with _LOCK:      # council 15/09: bound-check e pop sotto LO STESSO lock; audit PRIMA dell'effetto
                _scadenza_bacheca()
                r = next((x for x in BOARD if x["id"] == rid), None)
                if not r or not (0 <= idx < len(r.get("conferme") or [])):
                    return self._json(404, {"ok": False, "error": "nota inesistente"})
                audit = AB.registra_evento_sistema(f"prealert-{rid}/conferme/{idx}", "rimozione_nota",
                                                   motivo, operatore, nota_rimossa=r["conferme"][idx].get("nota", ""))
                rimossa = r["conferme"].pop(idx)
            return self._json(200, {"ok": True, "rimossa": rimossa.get("nota"),
                                    "audit": audit})
        if self.path in ("/operatori", "/operatori/revoca"):
            # SOLO il token di amministrazione (mai un token operatore) crea/revoca operatori (0.7.0)
            if getattr(self, "_op", None) is not None:
                return self._json(403, {"ok": False, "error": "solo il token di amministrazione gestisce gli operatori"})
            if self.path == "/operatori":
                try:
                    out = OP.crea(body.get("slug"), body.get("ruolo"), riemetti=bool(body.get("riemetti")), adotta_chiave=bool(body.get("adotta_chiave")))
                except OP.SlugEsistente as e:
                    return self._json(409, {"ok": False, "error": f"operatore '{e}' già registrato: per un nuovo token invia riemetti=true"})
                except PermissionError as e:
                    raise RegistroNonLeggibile(str(e))
                except ValueError as e:
                    return self._json(400, {"ok": False, "error": str(e)})
                try:
                    AB.registra_evento_sistema(f"sistema/operatori/{out['slug']}", out["evento"], f"ruolo {out['ruolo']}", "admin")
                except Exception:                            # noqa: BLE001 — atto amministrativo NON firmato: si annulla (review Opus r2)
                    OP.revoca(out["slug"]); raise
                return self._json(200, {"ok": True, **out, "nota": "il token è mostrato UNA volta; sul server resta solo il suo hash"})
            ok = OP.revoca(str(body.get("slug") or ""))
            if ok:
                AB.registra_evento_sistema(f"sistema/operatori/{body.get('slug')}", "revoca_operatore", "revoca", "admin")
            return self._json(200 if ok else 404, {"ok": ok})
        if self.path == "/ruota-token":
            if getattr(self, "_op", None) is not None:   # review Opus 18/09: un token operatore ruotava il token ADMIN e lo riceveva
                return self._json(403, {"ok": False, "error": "solo il token di amministrazione ruota il token"})
            # DICHIARATO alla DPGA (9C): «revoke access tokens at any time».
            # Il token corrente autentica la rotazione; il vecchio muore subito.
            # Anti self-bricking (fix Pro 06/09): il file è scritto PRIMA della
            # risposta; se la risposta si perde, il nuovo token è recuperabile
            # dall'amministratore sul server (team_token.txt) — dichiarato qui.
            nuovo = _nuovo_token()
            tmp = TOKEN_FILE + ".tmp"          # atomic: a reader never sees an empty token file (council 15/09, Gemini)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(nuovo)
            os.replace(tmp, TOKEN_FILE)
            audit = AB.registra_evento_sistema("sistema/token", "rotazione_token", "rotazione token di accesso",
                                               "admin")      # atto amministrativo: mai _operatore (in modalità pilota si auto-bloccava DOPO la scrittura)
            return self._json(200, {"ok": True, "nuovo_token": nuovo, "audit": audit})
        if self.path == "/ricezione":
            # Ricezione firmata del pre-alert nel PS (linea guida RCEM/AACE 2025: linea registrata,
            # clinico senior, risposta richiesta vs attuata con motivo se diversa). Valori chiusi +
            # digest: mai testo libero in chiaro nel ledger (verbale_probatorio.registra_ricezione).
            if not isinstance(body, dict):
                return self._json(400, {"ok": False, "error": "payload non conforme"})
            try:
                rid = int(body.get("id"))
            except (TypeError, ValueError):
                return self._json(400, {"ok": False, "error": "id non numerico"})
            with _LOCK:
                _scadenza_bacheca()
                r = next((x for x in BOARD if x["id"] == rid), None)
                if not r or r.get("prealert") is None:
                    return self._json(404, {"ok": False, "error": f"pre-alert {rid} inesistente o scaduto"})
                if len(r.setdefault("ricezioni", [])) >= CAP["ricezioni"]:
                    return self._json(429, {"ok": False, "error": "tetto ricezioni raggiunto"})
                out = VP.registra_ricezione(f"prealert-{rid}", self._operatore(body, "", "operatore_ps"),
                                            body.get("ruolo"), body.get("risposta_richiesta"),
                                            body.get("risposta_attuata"),
                                            motivo_alternativa=body.get("motivo_alternativa"),
                                            ts_emissione=r["ts"])
                if not out["ok"]:
                    return self._json(400, {"ok": False, "error": "ricezione non registrata", "problemi": out["problemi"]})
                r["ricezioni"].append({k: out[k] for k in ("ts", "latenza_s", "risposta_alternativa", "audit")})
                _persisti_record(r)
            return self._json(200, out)
        if self.path == "/prealert":
            # FIX 2026-09-11 (round 3): accettava un pre-alert PRE-CALCOLATO dal client con due soli campi
            # controllati → bypass del gate pediatrico e della validazione, PII arbitraria in bacheca
            # (misurato: eta_paziente 3 + nome → 200). Il server è l'UNICA fonte di verità: questo
            # endpoint resta per retro-compatibilità ma RICALCOLA da vitali/eta/farmaci come /valuta e
            # ignora ogni campo calcolato o non previsto inviato dal client.
            if not isinstance(body, dict) or "vitali" not in body or ("eta" not in body and "eta_mesi" not in body):
                return self._json(400, {"ok": False, "error": ("pre-alert non accettato: il pre-alert si calcola "
                                        "sul server — inviare vitali, eta, eta_arrivo_min (come /valuta)")})
            self.path = "/valuta"
            return self.do_POST_valuta(body)
        return self._json(404, {"ok": False, "error": "not found"})

    def log_message(self, *a):  # silenzioso
        pass


def serve(port=8097, host="127.0.0.1"):
    AB.esigi_firma_o_optin("team-comms")       # fail-closed (0.6.1): senza motore di firma il server non parte
    print(f"profilo d'uso: {profilo()} (INTENDED_USE.md)")
    try:
        OP.elenco()                            # permessi del registro operatori controllati all'avvio
    except PermissionError as e:
        raise SystemExit(f"registro operatori: {e}")
    rip = _ripristina_da_store()               # 0.7.0: journal cifrato opt-in (OMEGA_BOARD_STORE); senza = RAM come sempre
    if rip.get("store"):
        print(f"bacheca ripristinata da {rip['store']}: {rip['record']} record, {rip['incidenti']} incidenti, "
              f"{rip['scaduti_al_ripristino']} scaduti, {rip['scartati_senza_ts']} scartati senza istante; "
              f"non ripristinati (per design): {', '.join(rip['non_ripristinati'])}")
    livello = "part11" if AB.MOTORE_DISPONIBILE else ("firma-locale" if AB.FIRMA_LOCALE_DISPONIBILE else
                                                        "base (NON FIRMATO, opt-in; senza trail gli id NON sono stabili al riavvio)")
    print(f"OMEGA team-comms su http://{host}:{port}/  (bacheca PS) · token: {TOKEN_FILE} · audit: {livello}")
    _token()                                   # genera il token al primo avvio
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8097)
