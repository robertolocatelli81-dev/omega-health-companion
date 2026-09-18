#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Profilo d'uso (0.7.0, INTENDED_USE.md): in `comunicazione` NESSUN campo decisionale esce dal server e i campi tolti
sono elencati; in `punteggi` tutto come prima; un profilo sconosciuto ferma l'avvio."""
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

os.environ.setdefault("OMEGA_PACKAGE_DIR", "/nonexistent")
import ambulanza_intelligente as A
import audit_bridge as AB
import scores_emergenza as S
import team_comms as T

VIT = {"vitali": {"rr": 28, "spo2": 89, "su_ossigeno": True, "sbp": 85, "hr": 135, "alert_coscienza": True, "temp": 39.4}, "eta": 67, "eta_arrivo_min": 8,
       "farmaci": ["warfarin", "ibuprofene", "sildenafil"], "clinica": {"dolore_toracico": True}}   # sildenafil + dolore toracico → avviso nitrati


class TestProfilo(unittest.TestCase):
    def test_motore_non_eseguito_in_comunicazione(self):
        """Il pre-alert del profilo comunicazione nasce SENZA chiamare il motore (review Gemini 18/09)."""
        with mock.patch.object(A, "valuta_paziente", side_effect=AssertionError("motore chiamato")):
            p = T.prealert_comunicazione(VIT)
        self.assertEqual(p["profilo"], "comunicazione"); self.assertEqual(p["vitali"], VIT["vitali"]); self.assertEqual(p["avvisi"], [])
        for bad in ({**VIT, "eta": "67"}, {**VIT, "vitali": {**VIT["vitali"], "alert_coscienza": "no"}}, {**VIT, "eta_arrivo_min": 900},
                    {**VIT, "farmaci": [{"x": 1}]}, {k: v for k, v in VIT.items() if k != "eta"}):
            with self.assertRaises(ValueError):
                T.prealert_comunicazione(bad)

    def test_default_e_comunicazione(self):
        """Dal 0.7.2 il profilo di DEFAULT è comunicazione: senza OMEGA_PROFILO il motore non gira; punteggi è opt-in scritto."""
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != T.PROFILO_ENV}, clear=True):
            self.assertEqual(T.profilo(), "comunicazione")
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "punteggi"}):
            self.assertEqual(T.profilo(), "punteggi")

    def test_applica_profilo(self):
        out = A.valuta_paziente(VIT["vitali"], VIT["farmaci"], 67, 8, clinica=VIT["clinica"])["PRE_ALERT_INTEGRATO"]
        self.assertTrue(out["avvisi"], "il caso di test deve produrre un avviso (sildenafil + dolore toracico)")
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "comunicazione"}):
            p = T.applica_profilo(dict(out))
            for k in T.CAMPI_DECISIONALI:
                if k != "avvisi":                       # avvisi resta come lista VUOTA (la pagina lo legge)
                    self.assertNotIn(k, p, k)
            self.assertEqual(p["profilo"], "comunicazione"); self.assertIn("NEWS2", p["campi_non_calcolati"]); self.assertIn("interazioni_note", p["campi_non_calcolati"])
            self.assertEqual(p["vitali"], out["vitali"])                     # i vitali restano come inviati
            senza_elenco = {k: v for k, v in p.items() if k != "campi_non_calcolati"}
            for tell in ('"NEWS2":', '"priorita":', "GRAVE", "ALTO", "azione_raccomandata", "NITRATI", "⛔"):   # nessun VALORE decisionale, nemmeno annidato
                self.assertNotIn(tell, json.dumps(senza_elenco), tell)
            self.assertEqual(p["avvisi"], [])
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "punteggi"}):
            self.assertEqual(T.applica_profilo(dict(out)), out)
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "diagnosi"}):
            with self.assertRaises(SystemExit):
                T.profilo()


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente: questi test leggono il ledger locale FIRMATO")
class TestE2EProfilo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_prof_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl"); T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False; AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl"); AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        T.BOARD.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"; cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = cls._orig
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _req_text(self, method, path):
        req = urllib.request.Request(self.base + path, method=method, headers={"X-Omega-Token": self.token})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8")

    def _req(self, method, path, obj=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode() if obj is not None else None, method=method,
                                     headers={"Content-Type": "application/json", "X-Omega-Token": self.token})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())

    def test_comunicazione_end_to_end(self):
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != T.PROFILO_ENV}, clear=True):   # DEFAULT, non impostato
            st, out = self._req("POST", "/valuta", VIT)
            self.assertEqual(st, 200); p = out["prealert"]
            self.assertEqual(p["profilo"], "comunicazione"); self.assertNotIn("NEWS2", p); self.assertNotIn("priorita", p)
            st, board = self._req("GET", "/api/board")
            testo = json.dumps(board)
            for tell in ('"NEWS2":', '"priorita":', '"azione_raccomandata":', '"percorsi_attivare":'):
                self.assertNotIn(tell, testo, tell)
            st, fhir = self._req("GET", f"/fhir/{out['id']}")     # l'export FHIR R4 non contiene RiskAssessment né Flag nel profilo comunicazione
            self.assertNotIn("RiskAssessment", json.dumps(fhir)); self.assertNotIn('"Flag"', json.dumps(fhir)); self.assertNotIn("NITRATI", json.dumps(fhir))
            req = urllib.request.Request(self.base + f"/atmist/{out['id']}", headers={"X-Omega-Token": self.token})
            atm = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")   # testo semplice: ATMIST porta i vitali, non «NEWS2 None»
            self.assertNotIn("NEWS2", atm); self.assertIn("vitali come inviati", atm)
            import fhir_chems as C
            from chems_validate import SAMPLE_MISSION
            doc = C.prealert_to_chems_document(p, VIT["vitali"], "2026-09-18T10:40:00+02:00", SAMPLE_MISSION, provenienza_omega=out["provenienza"])
            self.assertNotIn("RiskAssessment", [e["resource"]["resourceType"] for e in doc["entry"]]); self.assertNotIn("NEWS2", json.dumps(doc))
            urls = {e["fullUrl"] for e in doc["entry"]}
            prov = next(e["resource"] for e in doc["entry"] if e["resource"]["resourceType"] == "Provenance")
            self.assertTrue(all(t["reference"] in urls for t in prov["target"]))   # nessun target pendente (review Opus 18/09)
            self.assertIsNone(out.get("tipo_paziente")); self.assertIn("tipo_paziente", p["campi_non_calcolati"])
            # SENZA provenienza, in ogni lingua: nessuna sezione con entry vuoto (il validator 6.10.4 lo rifiuta — misurato 18/09: 0 errori)
            for lang in ("de", "fr", "it", "en"):
                m = dict(SAMPLE_MISSION); m["lingua"] = lang
                d2 = C.prealert_to_chems_document(p, VIT["vitali"], "2026-09-18T10:40:00+02:00", m)
                def _walk(sec):
                    self.assertNotEqual(sec.get("entry"), [], "entry vuoto"); [_walk(x) for x in sec.get("section", [])]
                [_walk(sec) for sec in d2["entry"][0]["resource"]["section"]]
                self.assertIn(C.TEXTS[lang]["nota_profilo"][:20], json.dumps(d2, ensure_ascii=False))
            st, page = self._req_text("GET", "/?token=" + self.token)
            self.assertIn("vitali come inviati", page); self.assertNotIn("NEWS2 —", page)
            st, met = self._req("GET", "/metriche")            # niente «SCADUTO» per un pre-alert vivo senza priorità calcolata
            self.assertNotIn("SCADUTO", json.dumps(met)); self.assertIn("NON_CALCOLATA", json.dumps(met))
            # Un adulto, un bambino (3 anni) e un caso di interazione nota (sildenafil + nitrato): sotto il DEFAULT nessuna
            # uscita del server — bacheca, metriche, incidenti, pagina, FHIR, ATMIST, documento CH EMS — porta una chiave
            # decisionale né tipo_paziente né la raccomandazione sui nitrati (review Opus/Haiku 18/09: prima si guardava solo /valuta)
            st, inc = self._req("POST", "/incidente", {"descrizione": "tamponamento A4", "operatore": "co118"}); self.assertEqual(st, 200, inc)
            iid = inc["incidente"]["id"]
            casi = [dict(VIT, eta=3, vitali={"hr": 150, "rr": 35, "spo2": 94, "sbp": 85, "temp": 39.2, "su_ossigeno": False, "alert_coscienza": True}),
                    dict(VIT, eta=64.0, farmaci=["sildenafil", "nitroglicerina"], incidente_id=iid)]   # 64.0: contratto del motore (review Opus r2)
            ids = [out["id"]]; prealerts = [p]
            for c in casi:
                st, o = self._req("POST", "/valuta", c); self.assertEqual(st, 200, o); ids.append(o["id"]); prealerts.append(o["prealert"])
                self.assertIsNone(o.get("tipo_paziente")); self.assertEqual(o["prealert"]["avvisi"], [])
                self.assertEqual(o["prealert"]["campi_ignorati"], ["clinica"])   # dolore_toracico: input del motore, qui dichiarato ignorato
            st, es = self._req("POST", "/esito", {"id": ids[-1], "operatore_ps": "dr-z", "esito": "percorso_confermato"}); self.assertEqual(st, 200, es)
            def _chiavi(x, acc):
                if isinstance(x, dict):
                    acc.update(x.keys()); [_chiavi(v, acc) for v in x.values()]
                elif isinstance(x, list):
                    [_chiavi(v, acc) for v in x]
                return acc
            uscite = {"/api/board": self._req("GET", "/api/board")[1], "/metriche": self._req("GET", "/metriche")[1],
                      "/incidenti": self._req("GET", "/incidenti")[1], f"/incidente/{iid}": self._req("GET", f"/incidente/{iid}")[1]}
            self.assertEqual(uscite[f"/incidente/{iid}"]["pazienti"], 1)          # l'incidente ha davvero un paziente: la scansione non è a vuoto
            self.assertIsNone(uscite["/metriche"]["over_triage_proxy"])         # proxy NON_CALCOLATI, non zeri strutturali (review Opus r2)
            self.assertIn("NON_CALCOLATI", uscite["/metriche"]["nota"])
            for i in ids:
                uscite[f"/fhir/{i}"] = self._req("GET", f"/fhir/{i}")[1]
            for n, pp in enumerate(prealerts):                                    # documento CH EMS costruito da OGNI caso (libreria)
                uscite[f"chems/{n}"] = C.prealert_to_chems_document(pp, pp["vitali"], "2026-09-18T10:40:00+02:00", SAMPLE_MISSION)
            vietate = set(T.CAMPI_DECISIONALI) - {"avvisi"}     # avvisi resta come chiave, e ogni sua occorrenza deve essere [] (sotto)
            def _valori(x, chiave, acc):                          # ogni valore di `chiave` a qualunque profondità (review Sonnet r2: avvisi non
                if isinstance(x, dict):                           # è solo «NITRATI», è il campo delle raccomandazioni calcolate)
                    [acc.append(v) for k, v in x.items() if k == chiave]; [_valori(v, chiave, acc) for v in x.values()]
                elif isinstance(x, list):
                    [_valori(v, chiave, acc) for v in x]
                return acc
            # controllo positivo DEL BANCO, in codice: lo scanner deve vedere una chiave iniettata e un avviso iniettato
            finto = {"a": [{"b": {"NEWS2": 5}}], "c": {"avvisi": ["x"]}}
            self.assertTrue(_chiavi(finto, set()) & vietate); self.assertEqual(_valori(finto, "avvisi", []), [["x"]])
            for nome, u in uscite.items():
                chiavi = _chiavi(u, set())
                self.assertFalse(chiavi & vietate, f"{nome}: {chiavi & vietate}")
                for av in _valori(u, "avvisi", []):
                    self.assertEqual(av, [], f"{nome}: avvisi non vuoto {av!r}")
                testo = json.dumps(u, ensure_ascii=False)
                self.assertNotIn("NITRATI", testo, nome)
                for tp in _valori(u, "tipo_paziente", []):
                    self.assertIsNone(tp, f"{nome}: tipo_paziente {tp!r}")
            for i in ids:
                req = urllib.request.Request(self.base + f"/atmist/{i}", headers={"X-Omega-Token": self.token})
                atm = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
                for k in vietate:
                    self.assertNotIn(k, atm, f"atmist {i}: {k}")
                self.assertNotIn("NITRATI", atm)
            st, page = self._req_text("GET", "/?token=" + self.token)
            self.assertNotIn("NITRATI", page); self.assertNotIn("pediatrico", page.lower()); self.assertNotIn("NEWS2 ", page)
            self.assertIn("nessun punteggio calcolato", page)                     # piè di pagina del profilo, non «gli score sono standard validati»
            self.assertNotIn("gli score sono", page)
            atm = urllib.request.urlopen(urllib.request.Request(self.base + f"/atmist/{ids[0]}", headers={"X-Omega-Token": self.token}), timeout=30).read().decode()
            self.assertNotIn("vedi percorsi", atm)
            with T._LOCK:                                                          # un pre-alert scaduto: la scheda non deve tornare a «NEWS2 —»
                T.BOARD[0]["prealert"] = None
            st, page = self._req_text("GET", "/?token=" + self.token)
            self.assertNotIn("NEWS2", page); self.assertIn("dati clinici rimossi", page)
        # nel ledger firmato non c'è comunque mai un punteggio (digest-only): controllo che regge in entrambi i profili
        self.assertNotIn('"NEWS2":', open(AB.FALLBACK_LEDGER).read())


if __name__ == "__main__":
    unittest.main()
