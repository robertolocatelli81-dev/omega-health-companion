#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Coordinamento (13/09/2026): ciò che i competitor fanno, verificato end-to-end sul server vero.
Sandbox totale (ledger, chiavi, token, bacheca); controlli negativi prima dei positivi."""
from __future__ import annotations
import json
import os
_PROFILO_PRIMA = [None]


def setUpModule():                         # questi test esercitano il profilo punteggi (default = comunicazione dal 0.7.2). Assegnazione ESPLICITA
    _PROFILO_PRIMA[0] = os.environ.get("OMEGA_PROFILO")   # (non setdefault: un OMEGA_PROFILO esportato non deve cambiare cosa si testa — Gemini+Opus 18/09)
    os.environ["OMEGA_PROFILO"] = "punteggi"              # e in setUpModule, non a livello di modulo: `unittest discover` importa TUTTI i file prima di
                                                          # eseguirli, e un set a import-time vale per il processo intero (misurato 18/09, review Sonnet)


def tearDownModule():                      # ripristino: il profilo non trapela nei file eseguiti dopo
    if _PROFILO_PRIMA[0] is None:
        os.environ.pop("OMEGA_PROFILO", None)
    else:
        os.environ["OMEGA_PROFILO"] = _PROFILO_PRIMA[0]
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import coordinamento as CO  # noqa: E402
import audit_bridge as AB  # noqa: E402
import scores_emergenza as S  # noqa: E402
import team_comms as T  # noqa: E402

STABILE = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72, alert_coscienza=True, temp=36.7)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class TestPuro(unittest.TestCase):
    def test_banco(self):
        self.assertTrue(CO.banco_controllo()["banco_sa_fallire"])

    def test_tipi_da_pre_alert_reale(self):
        import ambulanza_intelligente as A
        out = A.valuta_paziente(STABILE, [], 60, 10, clinica={"dolore_toracico": True, "ecg_stemi": True})["PRE_ALERT_INTEGRATO"]
        t = CO.classifica_tipo(out)
        self.assertEqual(t["team_da_allertare"][0], "cath_lab")
        out = A.valuta_paziente(STABILE, [], 60, 10, condizioni={"emergenza_gravidanza_precoce": True})["PRE_ALERT_INTEGRATO"]
        self.assertIn("ostetrico", CO.classifica_tipo(out)["tipi"])
        self.assertEqual(CO.classifica_tipo(A.valuta_paziente(STABILE, [], 60, 10)["PRE_ALERT_INTEGRATO"])["tipi"], ["generale"])

    def test_banco_del_banco(self):
        orig = CO.TIPI["stemi"]
        try:
            CO.TIPI["stemi"] = ("resus", "x")
            self.assertFalse(CO.banco_controllo()["banco_sa_fallire"])
        finally:
            CO.TIPI["stemi"] = orig


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestE2ECoordinamento(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_co_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, T.BOARD_TTL_H)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl")
        T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        T.BOARD.clear(); T.ALLEGATI.clear(); T.INCIDENTI.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, T.BOARD_TTL_H = cls._orig

    def _req(self, method, path, obj=None, token=True, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else None)
        h = {"Content-Type": "application/json", **({"X-Omega-Token": self.token} if token else {}), **(headers or {})}
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            r = urllib.request.urlopen(req, timeout=10)
            body = r.read()
            try:
                return r.status, json.loads(body)
            except ValueError:
                return r.status, body
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body
        except (BrokenPipeError, ConnectionResetError, urllib.error.URLError):
            return 413, None      # il server ha rifiutato (413) e chiuso PRIMA che il client finisse l'invio

    def test_flusso(self):
        # incidente maggiore
        self.assertEqual(self._req("POST", "/incidente", {"descrizione": ""})[0], 400)
        st, inc = self._req("POST", "/incidente", {"descrizione": "tamponamento A4 km 12", "operatore": "co118"})
        self.assertEqual(st, 200); iid = inc["incidente"]["id"]
        self.assertEqual(self._req("POST", "/valuta", {"vitali": STABILE, "eta": 40, "eta_arrivo_min": 15, "incidente_id": 99})[0], 400)
        st, out = self._req("POST", "/valuta", {"vitali": dict(STABILE, hr=132), "eta": 40, "eta_arrivo_min": 15,
                                                 "incidente_id": iid, "operatore": "eq-1"})
        self.assertEqual(st, 200); rid = out["id"]
        self.assertEqual(out["tipo_paziente"]["tipi"], ["generale"])
        st, out2 = self._req("POST", "/valuta", {"vitali": STABILE, "eta": 55, "eta_arrivo_min": 20, "incidente_id": iid,
                                                  "clinica": {"dolore_toracico": True, "ecg_stemi": True}})
        self.assertEqual(out2["tipo_paziente"]["team_da_allertare"][0], "cath_lab")
        st, ri = self._req("GET", f"/incidente/{iid}")
        self.assertEqual(ri["pazienti"], 2)
        self.assertEqual(self._req("GET", "/incidente/7")[0], 404)
        # posizione/ETA
        self.assertEqual(self._req("POST", "/posizione", {"id": rid, "lat": 95, "lon": 9.2, "eta_arrivo_min": 10})[0], 400)
        self.assertEqual(self._req("POST", "/posizione", {"id": rid, "lat": 45.46, "lon": 9.19, "eta_arrivo_min": "10"})[0], 400)
        st, p = self._req("POST", "/posizione", {"id": rid, "lat": 45.4642, "lon": 9.19, "eta_arrivo_min": 9})
        self.assertEqual(st, 200); self.assertEqual(p["audit"]["livello"], "firma-locale")
        self.assertEqual(self._req("POST", "/posizione", {"id": 999, "eta_arrivo_min": 9})[0], 404)
        # messaggi bidirezionali
        self.assertEqual(self._req("POST", "/messaggio", {"id": rid, "da": "medico", "operatore": "x", "testo": "ok"})[0], 400)
        self.assertEqual(self._req("POST", "/messaggio", {"id": rid, "da": "ps", "operatore": "dr-z", "testo": "x" * 301})[0], 400)
        st, m = self._req("POST", "/messaggio", {"id": rid, "da": "equipaggio", "operatore": "eq-1", "testo": "paziente peggiora, GCS 13"})
        self.assertEqual(st, 200)
        st, m = self._req("POST", "/messaggio", {"id": rid, "da": "ps", "operatore": "dr-z", "testo": "resus pronta, entrata B"})
        self.assertEqual(m["n"], 2)
        st, msgs = self._req("GET", f"/messaggi/{rid}")
        self.assertEqual([x["da"] for x in msgs["messaggi"]], ["equipaggio", "ps"])
        self.assertEqual(len(msgs["posizioni"]), 1)
        self.assertEqual(msgs["posizioni"][0]["lat"], 45.4642)
        # allegati: negativi prima
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, token=False, headers={"Content-Type": "image/png", "X-Omega-Tipo": "ecg"})[0], 401)
        st, e = self._req("POST", f"/allegato/{rid}", raw=b"GIF89a....", headers={"Content-Type": "image/png", "X-Omega-Tipo": "ecg"})
        self.assertEqual(st, 400); self.assertTrue(any("firma dei byte" in p for p in e["problemi"]))
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/gif", "X-Omega-Tipo": "foto"})[0], 400)
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "selfie"})[0], 400)
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=b"%PDF-" + b"0" * (CO.MAX_ALLEGATO + 1), headers={"Content-Type": "application/pdf", "X-Omega-Tipo": "documento"})[0], 413)
        self.assertEqual(self._req("POST", "/allegato/999", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "ecg"})[0], 404)
        st, a = self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "ecg", "X-Omega-Operatore": "eq-1"})
        self.assertEqual(st, 200); self.assertEqual(a["n"], 1)
        req = urllib.request.Request(self.base + f"/allegato/{rid}/1", headers={"X-Omega-Token": self.token})
        resp = urllib.request.urlopen(req, timeout=10)
        self.assertEqual(resp.read(), PNG)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertEqual(resp.headers.get("Content-Security-Policy"), "sandbox")
        self.assertEqual(self._req("GET", f"/allegato/{rid}/2")[0], 404)
        self.assertEqual(self._req("GET", f"/allegato/{rid}/1", token=False)[0], 401)
        # esito: close the loop
        self.assertEqual(self._req("POST", "/esito", {"id": rid, "operatore_ps": "dr-z", "esito": "guarito"})[0], 400)
        self.assertEqual(self._req("POST", "/esito", {"id": rid, "operatore_ps": "dr-z", "esito": "percorso_confermato", "diagnosi_confermata": "sì"})[0], 400)
        st, es = self._req("POST", "/esito", {"id": rid, "operatore_ps": "dr-z", "esito": "percorso_non_necessario",
                                               "diagnosi_confermata": False, "tempo_porta_intervento_min": 25, "nota": "MARIO ROSSI stabile"})
        self.assertEqual(st, 200)
        st, es2 = self._req("POST", "/esito", {"id": out2["id"], "operatore_ps": "dr-z", "esito": "percorso_confermato", "tempo_porta_intervento_min": 40})
        # stato PS (divert/capacità) a vocabolario chiuso, destinazione per digest
        self.assertEqual(self._req("POST", "/stato_ps", {"stato": "chiuso", "operatore_ps": "dr-z"})[0], 400)
        self.assertEqual(self._req("POST", "/stato_ps", {"stato": "dirotta", "operatore_ps": "dr-z"})[0], 400)
        st, sp = self._req("POST", "/stato_ps", {"stato": "dirotta", "operatore_ps": "dr-z", "destinazione_alternativa": "Ospedale Nord, Trauma Center"})
        self.assertEqual(st, 200); self.assertEqual(sp["stato_ps"]["stato"], "dirotta")
        st, v3 = self._req("POST", "/valuta", {"vitali": STABILE, "eta": 30, "eta_arrivo_min": 5, "triage_start": "giallo", "incidente_id": iid})
        self.assertEqual(v3["stato_ps"]["stato"], "dirotta")
        self.assertEqual(self._req("POST", "/valuta", {"vitali": STABILE, "eta": 30, "eta_arrivo_min": 5, "triage_start": "blu"})[0], 400)
        st, ri = self._req("GET", f"/incidente/{iid}")
        self.assertEqual(ri["per_triage_start"], {"giallo": 1})
        # re-triage firmato e aggiornabile
        self.assertEqual(self._req("POST", "/triage", {"id": v3["id"], "triage_start": "viola"})[0], 400)
        st, tr = self._req("POST", "/triage", {"id": v3["id"], "triage_start": "rosso", "operatore": "eq-2"})
        self.assertEqual(st, 200); self.assertEqual(tr["audit"]["livello"], "firma-locale")
        self.assertEqual(self._req("GET", f"/incidente/{iid}")[1]["per_triage_start"], {"rosso": 1})
        # id incidente MONOTONO anche dopo la scadenza di un incidente
        st, inc2 = self._req("POST", "/incidente", {"descrizione": "secondo"})
        self.assertGreater(inc2["incidente"]["id"], iid)
        # tetto allegati per record (RAM): l'11° è rifiutato con 429
        for _ in range(9):
            self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "foto"})[0], 200)
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "foto"})[0], 429)
        # ricezione su pre-alert inesistente → 404; su record vivo → firmata sotto lock
        self.assertEqual(self._req("POST", "/ricezione", {"id": 999, "operatore_ps": "a", "ruolo": "medico", "risposta_richiesta": "resus", "risposta_attuata": "resus"})[0], 404)
        self.assertEqual(self._req("POST", "/ricezione", {"id": rid, "operatore_ps": "dr-z", "ruolo": "clinico_senior", "risposta_richiesta": "resus", "risposta_attuata": "resus"})[0], 200)
        self._req("POST", "/stato_ps", {"stato": "accetta", "operatore_ps": "dr-z"})
        # l'ETA aggiornata NON muta il pre-alert ancorato: sta in eta_corrente
        st, msgs = self._req("GET", f"/messaggi/{rid}")
        self.assertEqual(msgs["eta_corrente_min"], 9)
        st, board = self._req("GET", "/api/board")
        self.assertEqual([b for b in board if b["id"] == rid][0]["prealert"]["eta_arrivo_stimato_min"], 15)
        # metriche QA/QI
        st, mt = self._req("GET", "/metriche")
        self.assertEqual(mt["pre_alert"], 3); self.assertEqual(mt["esiti_registrati"], 2)
        self.assertEqual(mt["ricezioni"], 1)
        self.assertEqual([x["id"] for x in mt["da_escalare"]], [])     # appena emessi: sotto i 120 s
        self.assertEqual(mt["over_triage_proxy"], 1)        # FC 132 → criteri 2025 indicato, esito non necessario
        self.assertEqual(mt["tempo_porta_intervento_min"]["mediana"], 32.5)
        # NIENTE testo libero né byte nel ledger: solo digest
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            led = f.read()
        import base64
        # i BYTE dell'allegato non devono stare nel ledger: si cerca la loro codifica base64 reale, non la
        # stringa «PNG» (una firma base64 casuale può contenerla: rosso in CI il 13/09)
        for s in ("MARIO ROSSI", "paziente peggiora", "resus pronta", base64.b64encode(PNG).decode()[:24],
                  "tamponamento", "Ospedale Nord", "45.46", "9.19"):
            self.assertNotIn(s, led)             # nemmeno la posizione (a ~1 km) va su disco: solo il digest
        self.assertIn("posizione_hmac_sha256", led); self.assertNotIn("posizione_sha256", led); self.assertIn("triage_start", led)
        self.assertNotIn("45.4", led)                     # no coordinate, no bare digest of it, on disk
        self.assertIn("apertura_incidente", led); self.assertIn("stato_ps", led)
        self.assertIn("aggiornamento_eta", led); self.assertIn("esito_clinico", led); self.assertIn("allegato", led)
        # il verbale elenca gli eventi di coordinamento firmati
        import verbale_probatorio as VP
        v = VP.verbale(f"prealert-{rid}")
        self.assertTrue(v["firme_tutte_verificate"])
        self.assertGreaterEqual(v["n_eventi"], 6)     # emissione + eta + 2 messaggi + allegato + esito
        # scadenza: allegati e messaggi spariscono con la bacheca, e NULLA si ripopola dopo (410)
        T.BOARD_TTL_H = 0.0
        self.assertEqual(self._req("GET", f"/allegato/{rid}/1")[0], 404)
        st, msgs = self._req("GET", f"/messaggi/{rid}")
        self.assertEqual(msgs["messaggi"], [])
        self.assertEqual(len(T.ALLEGATI), 0)
        self.assertEqual(self._req("POST", "/messaggio", {"id": rid, "da": "ps", "operatore": "dr-z", "testo": "tardi"})[0], 404)
        self.assertEqual(self._req("POST", f"/allegato/{rid}", raw=PNG, headers={"Content-Type": "image/png", "X-Omega-Tipo": "ecg"})[0], 404)
        st, msgs = self._req("GET", f"/messaggi/{rid}")
        self.assertEqual(msgs["messaggi"], [])
        self.assertEqual(msgs["esiti"], [])                   # anche esiti e ricezioni escono dalla RAM
        self.assertEqual(self._req("POST", "/esito", {"id": rid, "operatore_ps": "dr-z", "esito": "dimesso"})[0], 404)
        self.assertEqual(self._req("POST", "/ricezione", {"id": rid, "operatore_ps": "dr-z", "ruolo": "medico", "risposta_richiesta": "resus", "risposta_attuata": "resus"})[0], 404)
        # con TTL 0 anche gli incidenti (oltre 2×TTL) spariscono
        self.assertEqual(self._req("GET", "/incidenti")[1], [])
        # Content-Length negativo → 400, non hang
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        c.putrequest("POST", "/valuta"); c.putheader("X-Omega-Token", self.token); c.putheader("Content-Length", "-5"); c.endheaders()
        self.assertEqual(c.getresponse().status, 400)


if __name__ == "__main__":
    unittest.main(verbosity=1)
