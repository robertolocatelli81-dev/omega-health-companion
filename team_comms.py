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
_BOARD_SEQ = [0]             # id MONOTONO dei pre-alert (i record oltre 2×TTL vengono rimossi: len()+1 collideva)   # posizioni: taglio a 200 dopo append   # tetti per record (RAM)


def _token() -> str:
    if not os.path.exists(TOKEN_FILE):
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    with open(TOKEN_FILE) as f:
        return f.read().strip()


BOARD_TTL_H = float(os.environ.get("OMEGA_BOARD_TTL_H", "24"))


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
            n += 1
    # crescita illimitata (council 15/09): i record scaduti da oltre max(2×TTL, 24 h) escono del tutto dalla
    # bacheca (un record svuotato resta consultabile — 410, vuoto — per almeno un giorno)
    for r in [r for r in BOARD if r.get("scaduto")]:
        try:
            if (now - datetime.fromisoformat(r["ts"])).total_seconds() / 3600 > max(2 * BOARD_TTL_H, 24):
                BOARD.remove(r)
        except (KeyError, ValueError):
            pass
    # incidenti: la lista non cresceva mai (council 13/09) → oltre 2×TTL dall'apertura spariscono
    for i in [i for i in INCIDENTI if (now - datetime.fromisoformat(i["ts"])).total_seconds() / 3600 > 2 * BOARD_TTL_H]:
        INCIDENTI.remove(i)
    return n


def _pubblica(prealert: dict, vitali: dict | None,
              operatore: str = "equipaggio-ambulanza", incidente_id: int | None = None) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    prov = S.ancora_prealert(prealert, ts)          # digest-only di default
    with _LOCK:
        _BOARD_SEQ[0] += 1
        rid = _BOARD_SEQ[0]
        # audit Part 11 (ponte opzionale): CREATE firmato authorship; degrado
        # onesto a "base" se il motore privato non è presente sul sistema
        audit = AB.registra_prealert(f"prealert-{rid}",
                                     S._hash(prealert), operatore)
        rec = {"id": rid, "ts": ts, "prealert": prealert,
               "vitali": vitali, "provenienza": prov,
               "audit": audit, "conferme": [], "ricezioni": [], "messaggi": [], "posizioni": [],
               "allegati": [], "esiti": [], "incidente_id": incidente_id,
               "tipo_paziente": CO.classifica_tipo(prealert)}
        BOARD.append(rec)
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
        pa = r["prealert"] or {"priorita": "SCADUTO", "azione_raccomandata":
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
             · NEWS2 {html.escape(str(pa.get('NEWS2','—')))} · arrivo {html.escape(str(pa.get('eta_arrivo_stimato_min','?')))} min</div>
          <div class=az>{html.escape(str(pa.get('azione_raccomandata','')))}</div>
          <ul>{perc}{avv}</ul>
          <div class=meta>conferme: {conf} · <a href="/fhir/{r['id']}">FHIR</a> · <a href="/atmist/{r['id']}">ATMIST</a></div>
          <form method=post action=/conferma>
            <input type=hidden name=id value="{r['id']}">
            <input type=hidden name=token value="__TOKEN__">
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
NON un dispositivo medico; gli score sono standard validati, la decisione è del medico</div>"""


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
        return 200, {"ok": True, "id": rid, "n": len(r[lista]), "audit": audit, "record": r}


def _find(rid: int):
    with _LOCK:
        _scadenza_bacheca()            # round 3: /fhir e /atmist serviranno 410 anche senza nuove POST
        for r in BOARD:
            if r["id"] == rid:
                return r
    return None


class H(BaseHTTPRequestHandler):
    timeout = 30            # Slowloris: un body dichiarato ma mai inviato libera il thread dopo 30 s (socket.timeout)
    server_version = "omega-team/1.0"

    def _read_body(self, n: int, deadline_s: float = 15.0):
        """Reads n bytes in chunks under an ABSOLUTE deadline (council 15/09, Gemini: the per-read socket timeout
        did not stop a body trickled at one byte per second for hours). None = not received in time."""
        import time
        t0, buf = time.monotonic(), bytearray()
        while len(buf) < n:
            if time.monotonic() - t0 > deadline_s:
                return None
            try:
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

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _authed(self, qs_token: str | None = None) -> bool:
        tok = self.headers.get("X-Omega-Token") or qs_token
        return bool(tok) and secrets.compare_digest(tok, _token())

    def _is_loopback(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            if not (self._is_loopback() or self._authed()):
                return self._send(401, "token richiesto")
            return self._send(200, _pagina().replace("__TOKEN__", _token() if self._is_loopback() else ""))
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
                       "vedi pre-alert", "vedi percorsi", r["prealert"],
                       trattamenti=[])
        return self._send(200, at["testo_consegna"], "text/plain; charset=utf-8")

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._json(400, {"ok": False, "error": "Content-Length invalido"})
        if n < 0:
            return self._json(400, {"ok": False, "error": "Content-Length invalido"})
        if self.path.startswith("/allegato/"):
            return self.do_POST_allegato(n)          # binario: mai decodificato come testo
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
            operatore = q.get("operatore", ["team-ps"])[0][:60] or "team-ps"
            if nota:
                # ricontrollo di scadenza e tetto SOTTO il lock, firma DOPO il ricontrollo (council 15/09: la conferma
                # era l'unica lista senza tetto, sopravviveva alla scadenza ed era firmata prima del ricontrollo)
                with _LOCK:
                    _scadenza_bacheca()
                    r = next((x for x in BOARD if x["id"] == rid), None)
                    if r and r.get("prealert") is not None and len(r.setdefault("conferme", [])) < CAP["conferme"]:
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
                            operatore=str(body.get("operatore") or "equipaggio-ambulanza")[:60], incidente_id=inc)
            if ts_start is not None:          # tag iniziale: firmato come ogni decisione clinica
                _evento_su_record(rec["id"], "triage", "triage_start", {"triage_start": ts_start},
                                  str(body.get("operatore") or "equipaggio-ambulanza")[:60],
                                  {"triage_start": ts_start, "operatore": str(body.get("operatore") or "equipaggio-ambulanza")[:60]})
                with _LOCK:
                    rec["triage_start"] = ts_start
            with _LOCK:
                stato_ps = dict(STATO_PS)
            return self._json(200, {"ok": True, "id": rec["id"],
                                    "prealert": out["PRE_ALERT_INTEGRATO"],
                                    "tipo_paziente": rec["tipo_paziente"], "stato_ps": stato_ps,
                                    "provenienza": rec["provenienza"]})

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
        operatore = (self.headers.get("X-Omega-Operatore") or "equipaggio-ambulanza")[:60]
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
        if self.path == "/incidente":
            desc = str(body.get("descrizione") or "")[:120].strip()
            operatore = str(body.get("operatore") or "centrale")[:60]
            if not desc:
                return self._json(400, {"ok": False, "error": "descrizione richiesta (≤120 caratteri)"})
            with _LOCK:
                if len(INCIDENTI) >= CAP["incidenti"]:
                    return self._json(429, {"ok": False, "error": "tetto incidenti aperti raggiunto"})
                _INCIDENTE_SEQ[0] += 1
                inc = {"id": _INCIDENTE_SEQ[0], "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "descrizione": desc, "aperto_da": operatore}      # descrizione SOLO in memoria
                INCIDENTI.append(inc)
            # nel ledger va il DIGEST della descrizione (luogo/targhe/nomi = testo libero), evento CREATE firmato
            audit = AB.registra_evento_clinico(f"incidente-{inc['id']}", "apertura_incidente",
                                               {"descrizione": CO.impronta_testo(desc)}, operatore)
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
            op = str(body.get("operatore") or "equipaggio-ambulanza")[:60]
            code, out = _evento_su_record(rid, "triage", "triage_start", {"triage_start": tag}, op, {"triage_start": tag, "operatore": op})
            if code == 200:
                with _LOCK:
                    out["record"]["triage_start"] = tag
                out = {k: v for k, v in out.items() if k != "record"}
            return self._json(code, out)
        if self.path == "/stato_ps":
            # divert / capacità (colonna portante di Pulsara/Twiage): il PS dichiara se accetta, è saturo o dirotta
            stato, op, dest = body.get("stato"), str(body.get("operatore_ps") or "")[:60], body.get("destinazione_alternativa")
            problemi = CO.valida_stato_ps(stato, op, dest)
            if problemi:
                return self._json(400, {"ok": False, "error": "stato rifiutato", "problemi": problemi})
            imp, sale = (CO.impegno(dest) if dest else (None, None))
            det = {"stato": stato, "destinazione_alternativa": imp}
            with _LOCK:      # audit e stato sotto lo stesso lock: l'ordine nel ledger = l'ordine in memoria
                audit = AB.registra_evento_clinico("ps", "stato_ps", det, op)
                STATO_PS.update({"stato": stato, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "operatore_ps": op, "destinazione_alternativa": dest, "sale": sale})
            return self._json(200, {"ok": True, "stato_ps": dict(STATO_PS), "audit": audit})
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
                                              str(body.get("operatore") or "equipaggio-ambulanza")[:60],
                                              {"lat": lat, "lon": lon, "eta_arrivo_min": eta, "ts": ev["ts"], "sale": sale})
                if code == 200:
                    with _LOCK:
                        out["record"]["posizioni"] = out["record"]["posizioni"][-200:]
                        out["record"]["eta_corrente"] = eta   # il pre-alert ancorato NON si muta
                    out = {"ok": True, "id": rid, "eta_arrivo_min": eta, "audit": out["audit"]}
                return self._json(code, out)
            if self.path == "/messaggio":
                da, op, testo = body.get("da"), str(body.get("operatore") or "")[:60], body.get("testo")
                problemi = CO.valida_messaggio(da, op, testo)
                if problemi:
                    return self._json(400, {"ok": False, "error": "messaggio rifiutato", "problemi": problemi})
                imp, sale = CO.impegno(testo)
                code, out = _evento_su_record(rid, "messaggi", "messaggio", {"da": da, **imp}, op,
                                              {"da": da, "operatore": op, "testo": testo, "ts": ts_now, "hmac_sha256": imp["hmac_sha256"], "sale": sale})
                return self._json(code, {k: v for k, v in out.items() if k != "record"})
            # /esito — close the loop
            op = str(body.get("operatore_ps") or "")[:60]
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
                operatore = str(body.get("operatore") or "team-ps")[:60]
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
        if self.path == "/ruota-token":
            # DICHIARATO alla DPGA (9C): «revoke access tokens at any time».
            # Il token corrente autentica la rotazione; il vecchio muore subito.
            # Anti self-bricking (fix Pro 06/09): il file è scritto PRIMA della
            # risposta; se la risposta si perde, il nuovo token è recuperabile
            # dall'amministratore sul server (team_token.txt) — dichiarato qui.
            import secrets as _sec
            nuovo = _sec.token_urlsafe(32)
            tmp = TOKEN_FILE + ".tmp"          # atomic: a reader never sees an empty token file (council 15/09, Gemini)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(nuovo)
            os.replace(tmp, TOKEN_FILE)
            audit = AB.registra_evento_sistema("sistema/token", "rotazione_token", "rotazione token di accesso",
                                               str(body.get("operatore") or "admin")[:60])
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
                out = VP.registra_ricezione(f"prealert-{rid}", str(body.get("operatore_ps") or "")[:60],
                                            body.get("ruolo"), body.get("risposta_richiesta"),
                                            body.get("risposta_attuata"),
                                            motivo_alternativa=body.get("motivo_alternativa"),
                                            ts_emissione=r["ts"])
                if not out["ok"]:
                    return self._json(400, {"ok": False, "error": "ricezione non registrata", "problemi": out["problemi"]})
                r["ricezioni"].append({k: out[k] for k in ("ts", "latenza_s", "risposta_alternativa", "audit")})
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
    print(f"OMEGA team-comms su http://{host}:{port}/  (bacheca PS) · token: {TOKEN_FILE}")
    _token()                                   # genera il token al primo avvio
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8097)
