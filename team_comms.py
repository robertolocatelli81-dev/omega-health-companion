#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — app di COMUNICAZIONE TEAM (ambulanza ↔ pronto soccorso, in tempo reale).

Web-app self-hosted (stdlib, zero dipendenze). L'ambulanza pubblica il pre-alert;
la bacheca del PS lo vede in tempo reale, con priorità/percorsi/provenienza; il
team conferma i percorsi ("stroke team pronto"). È il canale che coordina — come
Pulsara, ma open, self-hosted, con provenienza hash-chained.

Endpoints:
  GET  /                → bacheca PS (auto-refresh), pre-alert attivi
  POST /prealert        → l'ambulanza pubblica un pre-alert (JSON)
  POST /conferma        → il team conferma: {"id":..,"nota":".."}
  GET  /api/board       → lista pre-alert (JSON)

ONESTO: web-app dimostrativa, NON app mobile nativa. In produzione servono TLS,
autenticazione del personale, notifiche push e integrazione con il CAD/EHR.
Privacy: dati sanitari — qui in memoria locale; in prod cifratura + accesso ruolo.
"""
from __future__ import annotations
import json, html
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import scores_emergenza as S

# bacheca in memoria (in prod: store cifrato + audit ledger)
BOARD: list = []


def _pubblica(prealert: dict) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    prov = S.ancora_prealert(prealert, ts)          # provenienza hash-chained
    rec = {"id": len(BOARD) + 1, "ts": ts, "prealert": prealert,
           "provenienza": prov, "conferme": []}
    BOARD.append(rec)
    return rec


_COL = {"ALTO": "#c0392b", "MEDIO": "#e67e22", "BASSO": "#27ae60"}


def _pagina() -> str:
    righe = []
    for r in reversed(BOARD):
        pa = r["prealert"]; pr = pa.get("priorita", "—")
        perc = "".join(f"<li>{html.escape(p)}</li>" for p in pa.get("percorsi_attivare", [])) or "<li>—</li>"
        conf = "".join(f"<span class=ok>✓ {html.escape(c)}</span> " for c in r["conferme"]) or "<i>nessuna conferma</i>"
        sha = (r["provenienza"].get("self_hash") or "")[:16]
        righe.append(f"""
        <div class=card style="border-left:8px solid {_COL.get(pr,'#777')}">
          <div class=hdr><b>#{r['id']}</b> · <span class=pri style="background:{_COL.get(pr,'#777')}">{pr}</span>
             · NEWS2 {pa.get('NEWS2','?')} · arrivo {pa.get('eta_arrivo_stimato_min','?')} min</div>
          <ul>{perc}</ul>
          <div class=meta>conferme: {conf}</div>
          <form method=post action=/conferma>
            <input type=hidden name=id value="{r['id']}">
            <input name=nota placeholder="conferma percorso (es. stroke team pronto)">
            <button>Conferma</button>
          </form>
          <div class=sha>🔒 provenienza {sha}…</div>
        </div>""")
    return f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>
<title>OMEGA · Bacheca Pronto Soccorso</title>
<style>body{{font-family:system-ui;margin:0;background:#0f1419;color:#e6e6e6}}
h1{{background:#16213e;margin:0;padding:14px 18px;font-size:18px}}
.card{{background:#1b2430;margin:12px 18px;padding:12px 16px;border-radius:8px}}
.pri{{color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold}}
.hdr{{font-size:15px;margin-bottom:6px}} ul{{margin:6px 0}} li{{margin:2px 0}}
.meta{{font-size:13px;color:#9aa}} .ok{{color:#27ae60}} .sha{{font-size:11px;color:#667;margin-top:6px}}
input,button{{padding:6px;margin-top:6px}} button{{background:#0f3460;color:#fff;border:0;border-radius:4px;cursor:pointer}}
</style><h1>🚑 OMEGA · Bacheca Pronto Soccorso — pre-alert in arrivo (auto-refresh 5s)</h1>
{''.join(righe) or '<div class=card>Nessun pre-alert attivo.</div>'}"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.end_headers(); self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, _pagina())
        elif self.path == "/api/board":
            self._send(200, json.dumps(BOARD, ensure_ascii=False), "application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        if self.path == "/prealert":
            try:
                rec = _pubblica(json.loads(raw))
                self._send(200, json.dumps({"ok": True, "id": rec["id"],
                           "provenienza": rec["provenienza"]}, ensure_ascii=False), "application/json")
            except Exception as e:
                self._send(400, json.dumps({"ok": False, "error": str(e)}), "application/json")
        elif self.path == "/conferma":
            from urllib.parse import parse_qs
            q = parse_qs(raw)
            idx = int(q.get("id", ["0"])[0]); nota = (q.get("nota", [""])[0])[:100]
            for r in BOARD:
                if r["id"] == idx and nota:
                    r["conferme"].append(nota)
            self._send(303, ""); self.send_header("Location", "/")   # redirect
        else:
            self._send(404, "not found")

    def log_message(self, *a):  # silenzioso
        pass


def serve(port=8097, host="127.0.0.1"):
    print(f"OMEGA team-comms su http://{host}:{port}/  (bacheca PS)")
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8097)
