#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA health-companion — suite REALE: unit (i 5 banchi) + E2E su HTTP vero.

Guardie: il ledger di PRODUZIONE non viene mai toccato (LEDGER monkeypatchato in
tempdir a setUp); il server gira su porta effimera in-process; controlli negativi
prima dei positivi (auth respinta, input invalidi, pediatrico rifiutato)."""
from __future__ import annotations
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import scores_emergenza as S  # noqa: E402
import barella_prealert as B  # noqa: E402
import interazioni_farmaci as F  # noqa: E402
import ambulanza_intelligente as A  # noqa: E402
import fhir_export as FX  # noqa: E402
import audit_bridge as AB  # noqa: E402
import team_comms as T  # noqa: E402

VITALI_CRITICI = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
                      alert_coscienza=False, temp=39.4)
VITALI_STABILI = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72,
                      alert_coscienza=True, temp=36.7)


class TestBanchi(unittest.TestCase):
    """I 5 banchi (ognuno con controllo positivo + null) come unittest."""

    def test_tutti_i_banchi_sanno_fallire(self):
        for mod in (S, B, F, A, FX, AB):
            with self.subTest(modulo=mod.__name__):
                self.assertTrue(mod.banco_controllo()["banco_sa_fallire"])

    def test_il_banco_sa_DAVVERO_fallire(self):
        # controllo del controllore: un banco mutato DEVE andare rosso
        orig = F.INTERAZIONI
        try:
            F.INTERAZIONI = []          # niente registro → i positivi falliscono
            self.assertFalse(F.banco_controllo()["banco_sa_fallire"])
        finally:
            F.INTERAZIONI = orig


class TestE2E(unittest.TestCase):
    """Server VERO su porta effimera; ledger in sandbox; auth prima di tutto."""

    @classmethod
    def setUpClass(cls):
        cls._ledger_orig = S.LEDGER
        S.LEDGER = os.path.join(tempfile.mkdtemp(prefix="health_e2e_"), "ledger.jsonl")
        cls._tok_orig = T.TOKEN_FILE
        T.TOKEN_FILE = os.path.join(os.path.dirname(S.LEDGER), "token.txt")
        # sandbox anche l'audit Part 11 (trail + chiavi operatore): mai produzione
        cls._ab_orig = (AB.TRAIL_PATH, AB.KEYS_DIR, AB._trail, dict(AB._identita))
        AB.TRAIL_PATH = os.path.join(os.path.dirname(S.LEDGER), "p11_trail.jsonl")
        AB.KEYS_DIR = os.path.join(os.path.dirname(S.LEDGER), "p11_keys")
        AB._trail = None
        AB._identita.clear()
        T.BOARD.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        S.LEDGER = cls._ledger_orig
        T.TOKEN_FILE = cls._tok_orig
        AB.TRAIL_PATH, AB.KEYS_DIR, AB._trail, ids = cls._ab_orig
        AB._identita.clear()
        AB._identita.update(ids)

    def _post(self, path, obj, token=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json",
                                              **({"X-Omega-Token": token} if token else {})})
        try:
            r = urllib.request.urlopen(req, timeout=10)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _get(self, path, token=None, raw=False):
        req = urllib.request.Request(self.base + path,
                                     headers={"X-Omega-Token": token} if token else {})
        try:
            r = urllib.request.urlopen(req, timeout=10)
            body = r.read()
            return r.status, (body if raw else json.loads(body))
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_01_auth_respinta_senza_token(self):
        code, out = self._post("/valuta", {"vitali": VITALI_STABILI, "eta_arrivo_min": 5})
        self.assertEqual(code, 401)
        code, _ = self._get("/api/board")
        self.assertEqual(code, 401)

    def test_02_valuta_end_to_end(self):
        code, out = self._post("/valuta", {"vitali": VITALI_CRITICI,
                                           "farmaci": ["warfarin", "aspirina"],
                                           "eta": 67, "eta_arrivo_min": 8}, self.token)
        self.assertEqual(code, 200)
        self.assertTrue(out["ok"])
        self.assertEqual(out["prealert"]["priorita"], "ALTO")
        self.assertTrue(out["prealert"]["flag_farmacologico"])
        self.assertTrue(out["provenienza"]["ancorato"])
        self.assertEqual(out["provenienza"]["payload"], "digest")
        # il ledger sandbox contiene SOLO digest, mai vitali
        led = open(S.LEDGER).read()
        self.assertNotIn('"vitali"', led)
        self.assertIn("prealert_sha256", led)
        # bacheca
        code, board = self._get("/api/board", self.token)
        self.assertEqual(code, 200)
        self.assertEqual(board[-1]["id"], out["id"])

    def test_03_fhir_del_prealert(self):
        code, out = self._post("/valuta", {"vitali": VITALI_CRITICI, "farmaci": [],
                                           "eta": 70, "eta_arrivo_min": 6}, self.token)
        rid = out["id"]
        code, bundle = self._get(f"/fhir/{rid}", self.token)
        self.assertEqual(code, 200)
        self.assertEqual(bundle["resourceType"], "Bundle")
        tipi = [e["resource"]["resourceType"] for e in bundle["entry"]]
        self.assertIn("RiskAssessment", tipi)
        self.assertIn("Provenance", tipi)
        self.assertTrue(all(e.get("fullUrl", "").startswith("urn:uuid:") for e in bundle["entry"]))

    def test_04_atmist(self):
        code, out = self._post("/valuta", {"vitali": VITALI_STABILI, "farmaci": [],
                                           "eta": 45, "eta_arrivo_min": 12,
                                           "fast_segni": {"face": True}}, self.token)
        code, txt = self._get(f"/atmist/{out['id']}", self.token, raw=True)
        self.assertEqual(code, 200)
        self.assertIn(b"ATMIST", txt)
        self.assertIn(b"A: 45", txt)

    def test_05_pediatrico_rifiutato_via_api(self):
        code, out = self._post("/valuta", {"vitali": VITALI_STABILI, "eta": 4,
                                           "eta_arrivo_min": 10}, self.token)
        self.assertEqual(code, 200)
        self.assertEqual(out["prealert"]["priorita"], "NON_VALUTABILE_PEDIATRICO")

    def test_06_dati_invalidi_via_api(self):
        v = dict(rr=-5, spo2=150, su_ossigeno=False, sbp=999, hr=0,
                 alert_coscienza=True, temp=98.6)      # 98.6 = °F: deve dirlo
        code, out = self._post("/valuta", {"vitali": v, "eta": 50,
                                           "eta_arrivo_min": 10}, self.token)
        self.assertEqual(code, 200)
        self.assertEqual(out["prealert"]["priorita"], "NON_VALUTABILE_DATI_INVALIDI")
        self.assertTrue(any("°F" in p for p in out["prealert"]["problemi_dati"]))

    def test_07_prealert_precalcolato_malformato(self):
        code, out = self._post("/prealert", {"qualunque": 1}, self.token)
        self.assertEqual(code, 400)

    def test_08_json_rotto_e_payload_enorme(self):
        req = urllib.request.Request(self.base + "/valuta", data=b"{non-json",
                                     headers={"Content-Type": "application/json",
                                              "X-Omega-Token": self.token})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(cm.exception.code, 400)
        req = urllib.request.Request(self.base + "/valuta", data=b"x" * (T.MAX_BODY + 1),
                                     headers={"X-Omega-Token": self.token})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(cm.exception.code, 413)

    def test_08b_json_profondo_e_tipi_ostili_mai_crash(self):
        # regressione attacco 06/09: questi payload UCCIDEVANO il thread handler.
        # Esiti corretti: malformati → 400; vitali di tipo sbagliato → 200 con
        # rifiuto strutturato NON_VALUTABILE (fail-safe nominato, mai crash).
        for payload, attesi in (
                (("[" * 5000 + "]" * 5000).encode(), (400,)),          # RecursionError
                (b'"stringa"', (400,)),                                 # body non-oggetto
                (json.dumps({"vitali": "x", "eta_arrivo_min": 1}).encode(), (200,)),
                (json.dumps({"vitali": [1, 2], "eta_arrivo_min": 1}).encode(), (200,))):
            code, out = self._post("/valuta", None, self.token) if False else (None, None)
            req = urllib.request.Request(self.base + "/valuta", data=payload,
                                         headers={"Content-Type": "application/json",
                                                  "X-Omega-Token": self.token})
            try:
                resp = urllib.request.urlopen(req, timeout=10)
                code, body_out = resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                code, body_out = e.code, None
            self.assertIn(code, attesi, f"{payload[:30]} → {code}")
            if code == 200:   # il 200 è lecito SOLO come rifiuto strutturato
                self.assertEqual(body_out["prealert"]["priorita"],
                                 "NON_VALUTABILE_DATI_INVALIDI")
                self.assertTrue(any("vitali non è un oggetto" in p
                                    for p in body_out["prealert"]["problemi_dati"]))

    def test_09_conferma_dal_form(self):
        code, out = self._post("/valuta", {"vitali": VITALI_CRITICI, "eta": 60,
                                           "eta_arrivo_min": 7}, self.token)
        rid = out["id"]
        body = f"id={rid}&nota=stroke+team+pronto&operatore=dr-rossi&token={self.token}".encode()
        req = urllib.request.Request(self.base + "/conferma", data=body)
        r = urllib.request.urlopen(req, timeout=10)
        self.assertIn(r.status, (200, 303))
        code, board = self._get("/api/board", self.token)
        rec = [x for x in board if x["id"] == rid][0]
        conf = rec["conferme"][0]
        self.assertEqual(conf["nota"], "stroke team pronto")
        self.assertEqual(conf["operatore"], "dr-rossi")
        if AB.MOTORE_DISPONIBILE:      # col motore: firma part11 verificata
            self.assertEqual(conf["audit"]["livello"], "part11")
            self.assertTrue(conf["audit"]["firma_verificata"])
        else:                          # senza motore: degrado dichiarato, mai finto verde
            self.assertEqual(conf["audit"]["livello"], "base")

    def test_12_audit_trail_endpoint(self):
        code, out = self._get("/audit", self.token)
        self.assertEqual(code, 200)
        if AB.MOTORE_DISPONIBILE:
            self.assertEqual(out["livello"], "part11")
            self.assertTrue(out.get("record_digests_bound"))
        else:
            self.assertEqual(out["livello"], "base")

    def test_12b_rimuovi_nota_registrata_mai_silenziosa(self):
        code, out = self._post("/valuta", {"vitali": VITALI_STABILI, "eta": 50,
                                           "eta_arrivo_min": 9}, self.token)
        rid = out["id"]
        body = f"id={rid}&nota=da+rimuovere&operatore=dr-x&token={self.token}".encode()
        urllib.request.urlopen(urllib.request.Request(self.base + "/conferma", data=body),
                               timeout=10)
        # senza motivo → 400 (la rimozione silenziosa non esiste)
        code, out2 = self._post("/rimuovi-nota", {"id": rid, "indice_nota": 0,
                                                  "motivo": ""}, self.token)
        self.assertEqual(code, 400)
        code, out2 = self._post("/rimuovi-nota", {"id": rid, "indice_nota": 0,
                                                  "motivo": "inserita per errore",
                                                  "operatore": "dr-x"}, self.token)
        self.assertEqual(code, 200)
        self.assertEqual(out2["rimossa"], "da rimuovere")
        if AB.MOTORE_DISPONIBILE:      # la rimozione lascia traccia firmata
            self.assertEqual(out2["audit"]["livello"], "part11")
        code, board = self._get("/api/board", self.token)
        rec = [x for x in board if x["id"] == rid][0]
        self.assertEqual(rec["conferme"], [])

    def test_12c_rotazione_token_revoca_il_vecchio(self):
        code, out = self._post("/ruota-token", {"operatore": "admin-test"}, self.token)
        self.assertEqual(code, 200)
        nuovo = out["nuovo_token"]
        self.assertNotEqual(nuovo, self.token)
        code, _ = self._get("/api/board", self.token)     # vecchio token → morto
        self.assertEqual(code, 401)
        code, _ = self._get("/api/board", nuovo)          # nuovo token → vivo
        self.assertEqual(code, 200)
        type(self).token = nuovo                          # per i test successivi

    def test_13_prealert_ha_audit_authorship(self):
        code, out = self._post("/valuta", {"vitali": VITALI_STABILI, "eta": 55,
                                           "eta_arrivo_min": 9,
                                           "operatore": "equipaggio-118-alfa"}, self.token)
        code, board = self._get("/api/board", self.token)
        rec = [x for x in board if x["id"] == out["id"]][0]
        if AB.MOTORE_DISPONIBILE:
            self.assertEqual(rec["audit"]["livello"], "part11")
            self.assertEqual(rec["audit"]["significato"], "authorship")
            self.assertEqual(rec["audit"]["firmatario"], "equipaggio-118-alfa")
            self.assertTrue(rec["audit"]["firma_verificata"])
        else:
            self.assertEqual(rec["audit"]["livello"], "base")

    def test_10_catena_ledger_integra(self):
        righe = [json.loads(l) for l in open(S.LEDGER) if l.strip()]
        self.assertGreaterEqual(len(righe), 2)
        for prima, dopo in zip(righe, righe[1:]):
            self.assertEqual(dopo["prev_hash"], prima["self_hash"])

    def test_11_cli_ambulanza_contro_server_vero(self):
        import ambulanza_cli
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ambulanza_cli.main(["--rr", "28", "--spo2", "89", "--o2",
                                     "--sbp", "85", "--hr", "135", "--non-alert",
                                     "--temp", "39.4", "--eta", "67", "--arrivo", "8",
                                     "--farmaci", "warfarin", "aspirina",
                                     "--server", self.base, "--token", self.token])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["priorita"], "ALTO")
        self.assertTrue(out["provenienza"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
