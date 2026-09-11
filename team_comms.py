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
from typing import Optional
import secrets
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import ambulanza_intelligente as A
import audit_bridge as AB
import fhir_export as FX
import scores_emergenza as S

_HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(_HERE, "team_token.txt")
MAX_BODY = 64 * 1024          # un pre-alert è piccolo: payload enormi = rifiuto
BOARD: list = []
_LOCK = threading.Lock()


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
            continue
        try:
            eta_h = (now - datetime.fromisoformat(r["ts"])).total_seconds() / 3600
        except (KeyError, ValueError):
            continue
        if eta_h > BOARD_TTL_H:
            r["vitali"] = None
            r["prealert"] = None
            r["scaduto"] = True
            n += 1
    return n


def _pubblica(prealert: dict, vitali: dict | None,
              operatore: str = "equipaggio-ambulanza") -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    prov = S.ancora_prealert(prealert, ts)          # digest-only di default
    with _LOCK:
        rid = len(BOARD) + 1
        # audit Part 11 (ponte opzionale): CREATE firmato authorship; degrado
        # onesto a "base" se il motore privato non è presente sul sistema
        audit = AB.registra_prealert(f"prealert-{rid}",
                                     S._hash(prealert), operatore)
        rec = {"id": rid, "ts": ts, "prealert": prealert,
               "vitali": vitali, "provenienza": prov,
               "audit": audit, "conferme": []}
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


def _find(rid: int):
    with _LOCK:
        _scadenza_bacheca()            # round 3: /fhir e /atmist serviranno 410 anche senza nuove POST
        for r in BOARD:
            if r["id"] == rid:
                return r
    return None


class H(BaseHTTPRequestHandler):
    server_version = "omega-team/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
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
        for prefix, fn in (("/fhir/", self._fhir), ("/atmist/", self._atmist)):
            if self.path.startswith(prefix):
                try:
                    rid = int(self.path[len(prefix):])
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
        if n > MAX_BODY:
            return self._json(413, {"ok": False, "error": "payload troppo grande"})
        raw = self.rfile.read(n).decode(errors="replace")
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
            r = _find(rid)
            if r and nota:
                audit = AB.registra_conferma(f"prealert-{rid}", nota, operatore)
                with _LOCK:
                    r["conferme"].append({"nota": nota, "operatore": operatore,
                                          "audit": audit})
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
                    fast_segni=body.get("fast_segni"), clinica=body.get("clinica"))
            except ValueError as e:
                # messaggi NOSTRI (validazione nominata), mai il testo di un'eccezione interna
                return self._json(400, {"ok": False, "error": f"input invalido: {e}"})
            except (KeyError, TypeError, AttributeError):
                return self._json(400, {"ok": False, "error": "input invalido: struttura del payload non conforme"})
            except Exception:                                    # noqa: BLE001 — l'input arriva dalla rete
                return self._json(400, {"ok": False, "error": "input invalido"})
            rec = _pubblica(out["PRE_ALERT_INTEGRATO"], body.get("vitali"),
                            operatore=str(body.get("operatore") or "equipaggio-ambulanza")[:60])
            return self._json(200, {"ok": True, "id": rec["id"],
                                    "prealert": out["PRE_ALERT_INTEGRATO"],
                                    "provenienza": rec["provenienza"]})

    def do_POST_altri(self, body):
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
            r = _find(rid)
            if not r or not (0 <= idx < len(r["conferme"])):
                return self._json(404, {"ok": False, "error": "nota inesistente"})
            with _LOCK:
                rimossa = r["conferme"].pop(idx)
            audit = AB.registra_evento_sistema(f"prealert-{rid}/conferme/{idx}", "rimozione_nota",
                                               motivo, operatore, nota_rimossa=rimossa.get("nota", ""))
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
            fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(nuovo)
            audit = AB.registra_evento_sistema("sistema/token", "rotazione_token", "rotazione token di accesso",
                                               str(body.get("operatore") or "admin")[:60])
            return self._json(200, {"ok": True, "nuovo_token": nuovo, "audit": audit})
        if self.path == "/prealert":
            # FIX 2026-09-11 (round 3): accettava un pre-alert PRE-CALCOLATO dal client con due soli campi
            # controllati → bypass del gate pediatrico e della validazione, PII arbitraria in bacheca
            # (misurato: eta_paziente 3 + nome → 200). Il server è l'UNICA fonte di verità: questo
            # endpoint resta per retro-compatibilità ma RICALCOLA da vitali/eta/farmaci come /valuta e
            # ignora ogni campo calcolato o non previsto inviato dal client.
            if not isinstance(body, dict) or "vitali" not in body or "eta" not in body:
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
