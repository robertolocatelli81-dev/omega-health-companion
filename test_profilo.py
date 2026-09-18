#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Profilo d'uso (0.7.0, INTENDED_USE.md): in `comunicazione` NESSUN campo decisionale esce dal server e i campi tolti
sono elencati; in `punteggi` tutto come prima; un profilo sconosciuto ferma l'avvio."""
import json
import os
import re
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


# contratto del pre-alert nel profilo comunicazione: ALLOWLIST esatta (review Opus 18/09 r3: una blacklist che controlla
# una blacklist è una tautologia; un campo nuovo del motore non classificato deve far cadere un test, non passare)
CONTRATTO_COMUNICAZIONE = {"vitali", "eta_paziente", "eta_mesi", "eta_arrivo_stimato_min", "farmaci_in_uso", "avvisi", "profilo",
                           "campi_non_calcolati", "campi_ignorati", "nota_profilo"}
# chiavi NON decisionali che il motore (punteggi) può emettere: tutto il resto del suo output deve stare in CAMPI_DECISIONALI
MOTORE_NON_DECISIONALI = {"vitali", "eta_paziente", "eta_mesi", "eta_arrivo_stimato_min", "farmaci_in_uso", "problemi_dati"}


def _chiavi(x, acc):
    if isinstance(x, dict):
        acc.update(x.keys()); [_chiavi(v, acc) for v in x.values()]
    elif isinstance(x, list):
        [_chiavi(v, acc) for v in x]
    return acc


def _valori(x, chiave, acc):                          # ogni valore di `chiave` a qualunque profondità
    if isinstance(x, dict):
        [acc.append(v) for k, v in x.items() if k == chiave]; [_valori(v, chiave, acc) for v in x.values()]
    elif isinstance(x, list):
        [_valori(v, chiave, acc) for v in x]
    return acc


def _senza(x, chiavi):                                # copia senza le chiavi che ELENCANO legittimamente i nomi dei campi
    if isinstance(x, dict):
        return {k: _senza(v, chiavi) for k, v in x.items() if k not in chiavi}
    if isinstance(x, list):
        return [_senza(v, chiavi) for v in x]
    return x


ELENCHI = {"campi_non_calcolati", "nota_profilo", "nota", "campi_ignorati"}   # chiavi che ELENCANO nomi di campi, legittimamente


def _token_presente(k, testo):                        # token intero: «per_priorita» non è «priorita»
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(k) + r"(?![A-Za-z0-9_])", testo) is not None


class TestProfilo(unittest.TestCase):
    def test_deriva_motore_classificata(self):
        """Ogni chiave che il motore emette è o decisionale (CAMPI_DECISIONALI) o nell'allowlist non decisionale:
        una chiave nuova non classificata fa cadere QUESTO test invece di passare inosservata nel profilo comunicazione."""
        casi = [A.valuta_paziente(VIT["vitali"], VIT["farmaci"], 67, 8, clinica=VIT["clinica"]),
                A.valuta_paziente({"rr": 35, "spo2": 94, "su_ossigeno": False, "sbp": 85, "hr": 150, "alert_coscienza": True, "temp": 39.2}, [], 3, 8),
                A.valuta_paziente({"rr": 40, "spo2": 96, "su_ossigeno": False, "sbp": 80, "hr": 160, "alert_coscienza": True, "temp": 38.0}, [], 0, 8, eta_mesi=6),
                A.valuta_paziente(VIT["vitali"], ["warfarin"], 67, 8, fast_segni={"faccia": True}, condizioni={"ustione": True}, sepsi={"map_mmhg": 60}),
                A.valuta_paziente({**VIT["vitali"], "temp": 45}, [], 67, 8)]        # ramo NON_VALUTABILE_DATI_INVALIDI (problemi_dati)
        for out in casi:
            resto = set(out["PRE_ALERT_INTEGRATO"]) - set(T.CAMPI_DECISIONALI)
            self.assertTrue(resto <= MOTORE_NON_DECISIONALI, f"chiavi del motore non classificate: {resto - MOTORE_NON_DECISIONALI}")
        self.assertEqual(set(T.prealert_comunicazione(VIT)), CONTRATTO_COMUNICAZIONE)
        self.assertEqual(T.prealert_comunicazione({**VIT, "NEWS2": 9, "priorita": "ALTO"})["campi_ignorati"], ["NEWS2", "clinica", "priorita"])
        self.assertEqual(T.prealert_comunicazione({**VIT, "clinica": None, "fast_segni": None})["campi_ignorati"], [])   # null = assente (la CLI)
        for bad in ({**VIT, "priorita ALTA: NITRATI": 1}, {**VIT, **{f"k{i}": 1 for i in range(21)}}, {**VIT, "x" * 41: 1}):
            with self.assertRaises(ValueError):       # il NOME di una chiave ignota torna nella risposta: mai testo libero (review Opus r4)
                T.prealert_comunicazione(bad)

    def test_libreria_ignora_il_profilo(self):
        """La libreria calcola SEMPRE (il profilo governa il server, non il motore): pinnato, così una deriva in un senso o
        nell'altro si vede (review Opus 18/09 r3). La CLI invece NON calcola: è un client di /valuta (test e2e sotto)."""
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != T.PROFILO_ENV}, clear=True):
            out = A.valuta_paziente(VIT["vitali"], VIT["farmaci"], 67, 8, clinica=VIT["clinica"])["PRE_ALERT_INTEGRATO"]
            self.assertIsInstance(out["NEWS2"], int); self.assertTrue(out["avvisi"])
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "diagnosi"}):
            with self.assertRaises(SystemExit):        # valore non ammesso: il server NON parte, niente ripiego silenzioso
                T.profilo()

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
            # un client (es. CLI 0.7.1 o ePCR) che manda punteggi già calcolati: 200, nominati in campi_ignorati, mai serviti
            st, o = self._req("POST", "/valuta", dict(VIT, NEWS2=9, priorita="ALTO", azione_raccomandata="cath lab")); self.assertEqual(st, 200, o)
            ids.append(o["id"]); prealerts.append(o["prealert"])
            self.assertEqual(o["prealert"]["campi_ignorati"], ["NEWS2", "azione_raccomandata", "clinica", "priorita"])
            for pp in prealerts:
                self.assertEqual(set(pp), CONTRATTO_COMUNICAZIONE)                # allowlist esatta, non blacklist (review Opus r3)
            uscite = {}
            for nome in ("/api/board", "/metriche", "/incidenti", f"/incidente/{iid}", *[f"/fhir/{i}" for i in ids]):
                st, u = self._req("GET", nome); self.assertEqual(st, 200, nome); uscite[nome] = u    # stato asserito: mai scansione di un corpo d'errore
            self.assertEqual(len(uscite["/api/board"]), 4)
            for i in ids:
                self.assertEqual(uscite[f"/fhir/{i}"]["resourceType"], "Bundle"); self.assertTrue(uscite[f"/fhir/{i}"]["entry"])
            self.assertEqual(uscite[f"/incidente/{iid}"]["pazienti"], 1)          # l'incidente ha davvero un paziente: la scansione non è a vuoto
            self.assertIsNone(uscite["/metriche"]["over_triage_proxy"])         # proxy NON_CALCOLATI, non zeri strutturali (review Opus r2)
            self.assertIn("NON_CALCOLATI", uscite["/metriche"]["nota"])
            for n, pp in enumerate(prealerts):                                    # documento CH EMS costruito da OGNI caso (libreria)
                uscite[f"chems/{n}"] = C.prealert_to_chems_document(pp, pp["vitali"], "2026-09-18T10:40:00+02:00", SAMPLE_MISSION)
            vietate = set(T.CAMPI_DECISIONALI) - {"avvisi"}     # avvisi resta come chiave, e ogni sua occorrenza deve essere [] (sotto)
            # controlli positivi DEL BANCO, in codice, ciascuno da solo (review Opus r4: una sonda che contiene anche la chiave non
            # discrimina): chiave iniettata → la vede lo scanner a chiavi; punteggio come VALORE (FHIR code.text) → NON lo vede lo
            # scanner a chiavi, lo vede quello a token; avviso iniettato; e un controllo NEGATIVO: istogramma ed elenchi non sono fughe
            self.assertTrue(_chiavi({"a": [{"b": {"NEWS2": 5}}]}, set()) & vietate)
            valore = {"d": {"code": {"text": "NEWS2"}, "valueInteger": 5}}
            self.assertFalse(_chiavi(valore, set()) & vietate); self.assertTrue(_token_presente("NEWS2", json.dumps(_senza(valore, ELENCHI))))
            self.assertEqual(_valori({"c": {"avvisi": ["x"]}}, "avvisi", []), [["x"]])
            benigno = {"per_priorita": {"NON_CALCOLATA": 2}, "nota_profilo": "priorita non calcolata", "campi_non_calcolati": ["NEWS2"]}
            self.assertFalse(_chiavi(benigno, set()) & vietate)
            self.assertFalse([k for k in vietate if _token_presente(k, json.dumps(_senza(benigno, ELENCHI)))])
            for nome, u in uscite.items():
                chiavi = _chiavi(u, set())
                self.assertFalse(chiavi & vietate, f"{nome}: {chiavi & vietate}")
                for av in _valori(u, "avvisi", []):
                    self.assertEqual(av, [], f"{nome}: avvisi non vuoto {av!r}")
                testo = json.dumps(_senza(u, ELENCHI), ensure_ascii=False)         # scansione a TOKEN del testo, tolti gli elenchi legittimi
                for k in vietate:
                    self.assertFalse(_token_presente(k, testo), f"{nome}: token {k} nel testo")
                self.assertNotIn("nitrat", testo.lower(), nome)
                for tp in _valori(u, "tipo_paziente", []):
                    self.assertIsNone(tp, f"{nome}: tipo_paziente {tp!r}")
            for i in ids:
                req = urllib.request.Request(self.base + f"/atmist/{i}", headers={"X-Omega-Token": self.token})
                atm = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
                for k in vietate:
                    self.assertNotIn(k, atm, f"atmist {i}: {k}")
                self.assertNotIn("NITRATI", atm)
            # la CLI dell'ambulanza è un client di /valuta: contro il server di default stampa il profilo e la nota, non null muti
            import ambulanza_cli, contextlib, io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ambulanza_cli.main(["--rr", "28", "--spo2", "89", "--o2", "--sbp", "85", "--hr", "135", "--non-alert", "--temp", "39.4",
                                         "--eta", "67", "--arrivo", "8", "--farmaci", "warfarin", "--server", self.base, f"--token={self.token}"])
            self.assertEqual(rc, 0); cli = json.loads(buf.getvalue())
            self.assertEqual(cli["profilo"], "comunicazione"); self.assertIn("NON eseguito", cli["nota"] or ""); self.assertNotIn("NEWS2", cli)
            self.assertFalse(_chiavi(cli, set()) & vietate); ids.append(cli["id"])
            st, page = self._req_text("GET", "/?token=" + self.token)
            self.assertNotIn("nitrat", page.lower()); self.assertNotIn("pediatrico", page.lower()); self.assertNotIn("NEWS2", page)
            self.assertIn("nessun punteggio calcolato", page)                     # piè di pagina del profilo, non «gli score sono standard validati»
            self.assertNotIn("gli score sono", page)
            atm = urllib.request.urlopen(urllib.request.Request(self.base + f"/atmist/{ids[0]}", headers={"X-Omega-Token": self.token}), timeout=30).read().decode()
            self.assertNotIn("vedi percorsi", atm)
            with T._LOCK:                                                          # un pre-alert scaduto: la scheda non deve tornare a «NEWS2 —»
                T.BOARD[0]["prealert"] = None
            st, page = self._req_text("GET", "/?token=" + self.token)
            self.assertNotIn("NEWS2", page); self.assertIn("dati clinici rimossi", page); self.assertNotIn(">None<", page)
            self.assertIn("rimossi dalla bacheca dopo", page)                     # la nota di ritenzione resta (review Opus r3)
            with T._LOCK:                                                          # e il paziente dell'incidente scaduto: la riga non torna a «priorita: SCADUTO»
                next(x for x in T.BOARD if x.get("incidente_id") == iid)["prealert"] = None  # (review Gemini 18/09 r3)
            for nome in ("/incidenti", f"/incidente/{iid}"):
                u = self._req("GET", nome)[1]
                self.assertFalse(_chiavi(u, set()) & vietate, nome); self.assertIn('"scaduto": true', json.dumps(u))
        # nel ledger firmato non c'è comunque mai un punteggio (digest-only): controllo che regge in entrambi i profili
        self.assertNotIn('"NEWS2":', open(AB.FALLBACK_LEDGER).read())

    def test_punteggi_stessi_casi_lo_scanner_trova(self):
        """Controllo positivo degli SCENARI (review Opus 18/09 r3): gli stessi tre casi sotto punteggi devono produrre
        le chiavi decisionali, il tipo paziente del bambino, un avviso e il testo sui nitrati — altrimenti il test del
        default asserirebbe meno di quanto sembra."""
        vietate = set(T.CAMPI_DECISIONALI) - {"avvisi"}
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "punteggi"}):
            st, adulto = self._req("POST", "/valuta", VIT); self.assertEqual(st, 200)
            st, bimbo = self._req("POST", "/valuta", dict(VIT, eta=3, vitali={"hr": 150, "rr": 35, "spo2": 94, "sbp": 85, "temp": 39.2, "su_ossigeno": False, "alert_coscienza": True}))
            self.assertEqual(st, 200)
            st, inter = self._req("POST", "/valuta", dict(VIT, eta=64.0, farmaci=["sildenafil", "nitroglicerina"])); self.assertEqual(st, 200)
            st, board = self._req("GET", "/api/board"); self.assertEqual(st, 200)
            self.assertTrue(_chiavi(board, set()) & vietate)
            self.assertTrue(any(_valori(board, "avvisi", [])))
            self.assertEqual(bimbo["prealert"]["priorita"], "NON_VALUTABILE_PEDIATRICO"); self.assertIsNotNone(bimbo.get("tipo_paziente"))
            self.assertTrue(any("NITRATI" in a for a in inter["prealert"]["avvisi"] + adulto["prealert"]["avvisi"]))
            st, page = self._req_text("GET", "/?token=" + self.token); self.assertIn("NITRATI", page); self.assertIn("NEWS2", page)
            for k in vietate & {"NEWS2", "priorita"}:
                self.assertTrue(_token_presente(k, json.dumps(_senza(board, ELENCHI))))


if __name__ == "__main__":
    unittest.main()
