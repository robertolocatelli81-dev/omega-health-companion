#!/usr/bin/env python3
"""Regressioni del red-team dell'11/09/2026 (4 menti sul repo pubblico) — TIPI OSTILI via API.

Cosa era stato MISURATO prima del fix (POST /valuta con token valido):
  alert_coscienza="no"  → stringa truthy → paziente "cosciente" → priorità BASSO   (INVERSIONE clinica)
  su_ossigeno="false"   → stringa truthy → valutato come in ossigeno
  rr=true               → bool = 1.0 → RR 1/min → priorità MEDIO da un flag
  eta assente           → gate pediatrico saltato → score adulto (fail-OPEN)
  eta="4"               → TypeError con testo Python nella risposta 400
  eta=-3                → percorso pediatrico
  farmaci=[{...}]       → AttributeError nel handler → connessione chiusa senza risposta
Ogni caso qui era ROSSO prima del fix (controllo positivo del banco) e deve restare un rifiuto
NOMINATO: mai uno score da un tipo sbagliato, mai un'eccezione.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ambulanza_intelligente as A   # noqa: E402
import audit_bridge as AB            # noqa: E402
import barella_prealert as B         # noqa: E402
import scores_emergenza as S         # noqa: E402
import team_comms as T               # noqa: E402

VITALI_OK = {"rr": 18, "spo2": 97, "su_ossigeno": False, "sbp": 120, "hr": 80,
             "alert_coscienza": True, "temp": 37.0}


class TestValidazioneTipi(unittest.TestCase):
    def test_flag_clinici_stringa_rifiutati(self):
        for k, v in (("alert_coscienza", "no"), ("alert_coscienza", "false"), ("su_ossigeno", "false"),
                     ("su_ossigeno", 0), ("alert_coscienza", 1)):
            p = B.valida_vitali(dict(VITALI_OK, **{k: v}))
            self.assertTrue(any("non booleano" in x and k in x for x in p), (k, v, p))

    def test_numerici_bool_rifiutati(self):
        p = B.valida_vitali(dict(VITALI_OK, rr=True))
        self.assertTrue(any("non numerico: rr" in x for x in p), p)

    def test_numerici_stringa_rifiutati(self):
        p = B.valida_vitali(dict(VITALI_OK, hr="80"))
        self.assertTrue(any("non numerico: hr" in x for x in p), p)

    def test_non_finiti_rifiutati(self):
        for v in (float("nan"), float("inf")):
            p = B.valida_vitali(dict(VITALI_OK, sbp=v))
            self.assertTrue(p, v)

    def test_controllo_positivo_vitali_validi(self):
        self.assertEqual(B.valida_vitali(VITALI_OK), [])

    def test_eta_mancante_o_invalida_non_valutabile(self):
        for eta in (None, "4", -3, 200, True, float("nan")):
            out = A.valuta_paziente(VITALI_OK, [], eta, 10)["PRE_ALERT_INTEGRATO"]
            self.assertEqual(out["priorita"], "NON_VALUTABILE_DATI_INVALIDI", eta)
            self.assertTrue(any("eta" in p for p in out["problemi_dati"]), eta)

    def test_eta_pediatrica_resta_gate(self):
        out = A.valuta_paziente(VITALI_OK, [], 4.9, 10)["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_PEDIATRICO")

    def test_farmaci_tipo_sbagliato(self):
        for f in ("warfarin", [{"x": 1}], [1, 2]):
            with self.assertRaises(ValueError):
                A.valuta_paziente(VITALI_OK, f, 50, 10)


class TestAPITipiOstili(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp(prefix="health_types_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.TRAIL_PATH, AB.KEYS_DIR, AB._trail, dict(AB._identita))
        S.LEDGER = os.path.join(d, "ledger.jsonl")
        T.TOKEN_FILE = os.path.join(d, "token.txt")
        AB.TRAIL_PATH = os.path.join(d, "p11_trail.jsonl")
        AB.KEYS_DIR = os.path.join(d, "p11_keys")
        AB._trail = None
        AB._identita.clear()
        T.BOARD.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        S.LEDGER, T.TOKEN_FILE, AB.TRAIL_PATH, AB.KEYS_DIR, AB._trail, ident = cls._orig
        AB._identita.clear()
        AB._identita.update(ident)

    def _post(self, obj):
        req = urllib.request.Request(self.base + "/valuta", data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json",
                                              "X-Omega-Token": self.token})
        try:
            r = urllib.request.urlopen(req, timeout=10)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _base(self, **kw):
        v = dict(VITALI_OK, **kw)
        return {"vitali": v, "farmaci": [], "eta": 50, "eta_arrivo_min": 10}

    def test_controllo_positivo(self):
        code, out = self._post(self._base())
        self.assertEqual(code, 200)
        self.assertEqual(out["prealert"]["priorita"], "BASSO")

    def test_inversione_clinica_chiusa(self):
        for k, v in (("alert_coscienza", "no"), ("su_ossigeno", "false"), ("rr", True)):
            code, out = self._post(self._base(**{k: v}))
            self.assertEqual(code, 200, (k, v))
            self.assertEqual(out["prealert"]["priorita"], "NON_VALUTABILE_DATI_INVALIDI", (k, v))

    def test_eta_stringa_non_espone_eccezioni(self):
        code, out = self._post(dict(self._base(), eta="4"))
        self.assertEqual(code, 200)
        self.assertEqual(out["prealert"]["priorita"], "NON_VALUTABILE_DATI_INVALIDI")
        self.assertNotIn("TypeError", json.dumps(out))
        self.assertNotIn("not supported between", json.dumps(out))

    def test_farmaci_dict_risposta_pulita(self):
        code, out = self._post(dict(self._base(), farmaci=[{"x": 1}]))
        self.assertEqual(code, 400)
        self.assertIn("farmaci", out.get("error", ""))
        self.assertNotIn("AttributeError", json.dumps(out))


class TestRitenzioneBacheca(unittest.TestCase):
    def test_record_scaduto_svuotato_e_pagina_regge(self):
        from datetime import datetime, timezone, timedelta
        T.BOARD.clear()
        vecchio = (datetime.now(timezone.utc) - timedelta(hours=T.BOARD_TTL_H + 1)).isoformat()
        T.BOARD.append({"id": 1, "ts": vecchio, "prealert": {"priorita": "ALTO"}, "vitali": {"rr": 30},
                        "provenienza": {"self_hash": "x"}, "audit": {}, "conferme": []})
        self.assertEqual(T._scadenza_bacheca(), 1)
        self.assertIsNone(T.BOARD[0]["vitali"])
        self.assertIsNone(T.BOARD[0]["prealert"])
        self.assertIn("SCADUTO", T._pagina())
        T.BOARD.clear()


if __name__ == "__main__":
    unittest.main()
