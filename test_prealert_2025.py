#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Criteri di pre-alert RCEM/AACE 2025 + verbale probatorio — suite con controlli positivi e null.

Guardie: ledger e chiavi in sandbox (mai produzione); server su porta effimera; il banco dimostra
PRIMA di saper fallire (banco-del-banco: un valutatore rotto DEVE essere colto)."""
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
import prealert_criteria as PC  # noqa: E402
import verbale_probatorio as VP  # noqa: E402
import ambulanza_intelligente as A  # noqa: E402
import audit_bridge as AB  # noqa: E402
import scores_emergenza as S  # noqa: E402
import team_comms as T  # noqa: E402

STABILE = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72, alert_coscienza=True, temp=36.7)


def _v(**kw):
    d = dict(STABILE)
    d.update(kw)
    return d


class TestSoglieAdulto(unittest.TestCase):
    """Ogni soglia trascritta dalla linea guida, provata AI BORDI (dentro/fuori)."""

    def _crit(self, **kw):
        return [c["criterio"] for c in PC.criteri_adulto(_v(**kw))["criteri"]]

    def test_null_adulto_stabile(self):
        self.assertEqual(self._crit(), [])

    def test_frequenza_respiratoria_bordi(self):
        self.assertIn("frequenza respiratoria", self._crit(rr=8))
        self.assertNotIn("frequenza respiratoria", self._crit(rr=9))
        self.assertNotIn("frequenza respiratoria", self._crit(rr=24))
        self.assertIn("frequenza respiratoria", self._crit(rr=25))

    def test_spo2_solo_in_ossigeno(self):
        self.assertIn("SpO2 in ossigeno", self._crit(spo2=91, su_ossigeno=True))
        self.assertNotIn("SpO2 in ossigeno", self._crit(spo2=92, su_ossigeno=True))
        # in aria la linea guida non fissa la soglia adulta: nessun criterio (dichiarato)
        self.assertNotIn("SpO2 in ossigeno", self._crit(spo2=85, su_ossigeno=False))

    def test_spo2_ipercapnico(self):
        self.assertIn("SpO2 in ossigeno", self._crit(spo2=83, su_ossigeno=True, bpco_scala2=True))
        self.assertNotIn("SpO2 in ossigeno", self._crit(spo2=84, su_ossigeno=True, bpco_scala2=True))

    def test_pressione_e_frequenza_bordi(self):
        self.assertIn("pressione sistolica", self._crit(sbp=90))
        self.assertNotIn("pressione sistolica", self._crit(sbp=91))
        self.assertIn("frequenza cardiaca", self._crit(hr=40))
        self.assertNotIn("frequenza cardiaca", self._crit(hr=41))
        self.assertNotIn("frequenza cardiaca", self._crit(hr=130))
        self.assertIn("frequenza cardiaca", self._crit(hr=131))

    def test_gcs(self):
        self.assertIn("GCS", [c["criterio"] for c in PC.criteri_adulto(_v(), gcs=12)["criteri"]])
        self.assertNotIn("GCS", [c["criterio"] for c in PC.criteri_adulto(_v(), gcs=13)["criteri"]])

    def test_scope_dichiarato(self):
        nv = PC.criteri_adulto(_v())["non_valutato"]
        self.assertTrue(any("in calo" in x for x in nv))
        self.assertTrue(any("nuovo per il paziente" in x for x in nv))


class TestPediatrico(unittest.TestCase):
    """Tabella per fasce d'età: bordi per fascia, SpO2 in aria, CRT, GCS, lattante <3 mesi."""

    def _crit(self, eta, mesi=None, **kw):
        v = dict(rr=25, hr=110, spo2=98, su_ossigeno=False)
        v.update(kw)
        r = PC.criteri_pediatrici(eta, v, mesi)
        self.assertEqual(r["problemi_dati"], [])
        return [c["criterio"] for c in r["criteri"]]

    def test_fasce_rr_hr(self):
        # <1 anno: RR <20 o >60, HR <90 o >170
        self.assertIn("frequenza respiratoria", self._crit(0, rr=19))
        self.assertNotIn("frequenza respiratoria", self._crit(0, rr=20))
        self.assertIn("frequenza respiratoria", self._crit(0, rr=61))
        self.assertIn("frequenza cardiaca", self._crit(0, hr=89))
        self.assertNotIn("frequenza cardiaca", self._crit(0, hr=170))
        # 1-4: RR <20 o >50, HR <70 o >150
        self.assertIn("frequenza respiratoria", self._crit(3, rr=51))
        self.assertNotIn("frequenza respiratoria", self._crit(3, rr=50))
        self.assertIn("frequenza cardiaca", self._crit(4, hr=151))
        # 5-12: RR <15 o >40, HR <70 o >140
        self.assertIn("frequenza respiratoria", self._crit(9, rr=14))
        self.assertNotIn("frequenza respiratoria", self._crit(9, rr=40))
        self.assertIn("frequenza cardiaca", self._crit(12, hr=141))
        # 13-15: RR <10 o >30, HR <60 o >120
        self.assertIn("frequenza respiratoria", self._crit(15, rr=31))
        self.assertNotIn("frequenza cardiaca", self._crit(15, hr=120))
        self.assertIn("frequenza cardiaca", self._crit(13, hr=59))

    def test_spo2_in_aria_crt_gcs(self):
        self.assertIn("SpO2 in aria", self._crit(7, spo2=90))
        self.assertNotIn("SpO2 in aria", self._crit(7, spo2=91))
        self.assertNotIn("SpO2 in aria", self._crit(7, spo2=90, su_ossigeno=True))   # in O2 la soglia «on air» non vale
        self.assertIn("tempo di riempimento capillare", self._crit(7, crt_sec=3))
        self.assertNotIn("tempo di riempimento capillare", self._crit(7, crt_sec=2))
        self.assertIn("GCS", self._crit(10, gcs=12))
        self.assertIn("GCS modificato", self._crit(2, gcs=12))

    def test_lattante_temperatura(self):
        self.assertIn("temperatura (lattante <3 mesi)", self._crit(0, mesi=2, temp=38.0))
        self.assertNotIn("temperatura (lattante <3 mesi)", self._crit(0, mesi=2, temp=37.9))
        self.assertNotIn("temperatura (lattante <3 mesi)", self._crit(0, mesi=4, temp=39.0))
        # senza eta_mesi il criterio è dichiarato non valutato, non inventato
        r = PC.criteri_pediatrici(0, dict(rr=25, hr=110, spo2=98, su_ossigeno=False, temp=39.0))
        self.assertTrue(any("eta_mesi" in x for x in r["non_valutato"]))

    def test_tipi_ostili(self):
        r = PC.criteri_pediatrici(5, dict(rr="25", hr=110, spo2=98, su_ossigeno="no", extra=1))
        self.assertTrue(any("non numerico: rr" in p for p in r["problemi_dati"]))
        self.assertTrue(any("non booleano: su_ossigeno" in p for p in r["problemi_dati"]))
        self.assertTrue(any("extra" in p for p in r["problemi_dati"]))
        self.assertEqual(r["criteri"], [])


class TestCondizioniESepsi(unittest.TestCase):
    def test_condizione_sola_attiva_prealert(self):
        d = PC.decisione_prealert(60, _v(), condizioni={"asma_pericolo_di_vita": True})
        self.assertTrue(d["pre_alert_indicato"])
        self.assertEqual(d["condizioni_specifiche"][0]["linea_guida"], "Life-threatening asthma")

    def test_condizione_falsa_non_conta(self):
        d = PC.decisione_prealert(60, _v(), condizioni={"stemi": False})
        self.assertFalse(d["pre_alert_indicato"])

    def test_chiave_ignota_e_stringa_rifiutate(self):
        for cond in ({"infarto": True}, {"stemi": "no"}, "stemi"):
            d = PC.decisione_prealert(60, _v(), condizioni=cond)
            self.assertIsNone(d["pre_alert_indicato"])
            self.assertTrue(d["problemi_dati"])

    def test_sepsi_richiede_storia_infezione(self):
        crit = _v(rr=26, hr=132, sbp=88, alert_coscienza=False)
        s0 = PC.sepsi_alto_rischio_jrcalc(crit, {"cianosi": True}, storia_infezione=False)
        s1 = PC.sepsi_alto_rischio_jrcalc(crit, {"cianosi": True}, storia_infezione=True, news2=7)
        self.assertFalse(s0["alto_rischio"])
        self.assertTrue(s1["alto_rischio"])
        self.assertTrue(s1["news2_sospetto"])
        self.assertGreaterEqual(len(s1["marcatori"]), 5)
        d = PC.decisione_prealert(60, crit, sepsi=s1)
        self.assertTrue(any(c["condizione"] == "sepsi_alto_rischio_adulto" for c in d["condizioni_specifiche"]))

    def test_sepsi_segno_ignoto_rifiutato(self):
        s = PC.sepsi_alto_rischio_jrcalc(_v(), {"febbre": True}, storia_infezione=True)
        self.assertTrue(s["problemi_dati"])
        self.assertFalse(s["alto_rischio"])

    def test_messaggio_headline_ed_eta_prima(self):
        d = PC.decisione_prealert(67, _v(rr=26, sbp=85), gcs=12)
        at = {"ATMIST": {"A_eta": 67, "T_orario_evento": "10:20", "M_meccanismo_esordio": "dispnea",
                         "I_lesioni_problema": "BPCO nota", "S_segni": "RR 26 SBP 85", "T_trattamenti": ["O2"]}}
        m = PC.messaggio_prealert(d, 12, "resus", at)
        self.assertTrue(m["testo"].startswith("HEADLINE: resus"))
        self.assertLess(m["testo"].index("ETA"), m["testo"].index("ATMIST"))
        self.assertTrue(m["entro_60s"])
        with self.assertRaises(ValueError):
            PC.messaggio_prealert(d, -1, "resus", at)


class TestIntegrazioneMotore(unittest.TestCase):
    def test_adulto_criterio_isolato_alza_priorita(self):
        # FC 132 isolata: NEWS2 basso-medio ma criterio 2025 attivo → mai BASSO, azione coerente
        out = A.valuta_paziente(_v(hr=132), [], 50, 10)["PRE_ALERT_INTEGRATO"]
        self.assertTrue(out["criteri_prealert_2025"]["pre_alert_indicato"])
        self.assertNotEqual(out["priorita"], "BASSO")

    def test_adulto_stabile_nessun_prealert(self):
        out = A.valuta_paziente(_v(), [], 50, 10)["PRE_ALERT_INTEGRATO"]
        self.assertFalse(out["criteri_prealert_2025"]["pre_alert_indicato"])
        self.assertEqual(out["priorita"], "BASSO")

    def test_condizioni_derivate_dai_percorsi(self):
        out = A.valuta_paziente(_v(), [], 60, 10, clinica={"dolore_toracico": True, "ecg_stemi": True})["PRE_ALERT_INTEGRATO"]
        self.assertIn("stemi", [c["condizione"] for c in out["criteri_prealert_2025"]["condizioni_specifiche"]])

    def test_condizione_dichiarata_ostile_rifiutata(self):
        out = A.valuta_paziente(_v(), [], 60, 10, condizioni={"stemi": "sì"})["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_DATI_INVALIDI")
        self.assertTrue(any("condizioni.stemi" in p for p in out["problemi_dati"]))

    def test_pediatrico_criteri_senza_score(self):
        out = A.valuta_paziente(dict(rr=65, spo2=88, su_ossigeno=False, sbp=80, hr=150,
                                     alert_coscienza=True, temp=38.5), [], 0, 10, eta_mesi=6)["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_PEDIATRICO")
        self.assertNotIn("NEWS2", out)
        self.assertTrue(out["criteri_prealert_2025"]["pre_alert_indicato"])
        self.assertTrue(out["percorsi_attivare"][0].startswith("PRE-ALERT PEDIATRICO INDICATO"))

    def test_pediatrico_stabile_nessun_prealert(self):
        out = A.valuta_paziente(dict(rr=22, spo2=98, su_ossigeno=False, sbp=100, hr=95,
                                     alert_coscienza=True, temp=36.8), [], 8, 10)["PRE_ALERT_INTEGRATO"]
        self.assertFalse(out["criteri_prealert_2025"]["pre_alert_indicato"])

    def test_banco_del_banco_valutatore_rotto(self):
        """Il banco deve COGLIERE un valutatore rotto: soglia FC alta alzata a 200 → il caso positivo perde
        un criterio → banco_sa_fallire False. Ripristino garantito."""
        orig = PC.SOGLIE_ADULTO["hr_alta"]
        try:
            PC.SOGLIE_ADULTO["hr_alta"] = 200
            self.assertFalse(PC.banco_controllo()["banco_sa_fallire"])
        finally:
            PC.SOGLIE_ADULTO["hr_alta"] = orig
        self.assertTrue(PC.banco_controllo()["banco_sa_fallire"])


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente: livello base dichiarato")
class TestVerbale(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="verb_")
        self._orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(self.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(self.tmp, "keys")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = self._orig

    def test_ricezione_valori_chiusi(self):
        r = VP.registra_ricezione("prealert-1", "dr-x", "primario", "resus", "resus")
        self.assertFalse(r["ok"])
        r = VP.registra_ricezione("prealert-1", "dr-x", "medico", "resus", "chirurgia")
        self.assertFalse(r["ok"])
        r = VP.registra_ricezione("prealert-1", "", "medico", "resus", "resus")
        self.assertFalse(r["ok"])

    def test_alternativa_richiede_motivo_e_va_per_digest(self):
        r = VP.registra_ricezione("prealert-1", "dr-x", "clinico_senior", "trauma_team", "resus")
        self.assertFalse(r["ok"])
        r = VP.registra_ricezione("prealert-1", "dr-x", "clinico_senior", "trauma_team", "resus",
                                  motivo_alternativa="trauma team in sala; paziente MARIO ROSSI")
        self.assertTrue(r["ok"] and r["risposta_alternativa"])
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            disco = f.read()
        self.assertNotIn("MARIO ROSSI", disco)          # il motivo va per digest, mai in chiaro
        self.assertIn("motivo_alternativa", disco)

    def test_verbale_verifica_e_rileva_manomissione(self):
        AB.registra_prealert("prealert-9", "cd" * 32, "equipaggio-3")
        VP.registra_ricezione("prealert-9", "dr-y", "medico", "resus", "resus", ts_emissione="2026-09-13T10:00:00+00:00")
        v = VP.verbale("prealert-9")
        self.assertEqual(v["n_eventi"], 2)
        self.assertTrue(v["firme_tutte_verificate"])
        self.assertIsNotNone(v["latenza_emissione_ricezione_ms"])
        self.assertNotIn("vitali", json.dumps(v))
        # un altro pre-alert non entra nel verbale di questo
        AB.registra_prealert("prealert-99", "ef" * 32, "equipaggio-4")
        self.assertEqual(VP.verbale("prealert-9")["n_eventi"], 2)
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            lines = f.read().splitlines()
        lines[0] = lines[0].replace("equipaggio-3", "equipaggio-X")
        with open(AB.FALLBACK_LEDGER, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        v2 = VP.verbale("prealert-9")
        self.assertFalse(v2["firme_tutte_verificate"])
        self.assertFalse(v2["eventi"][0]["firma_ok"])
        self.assertTrue(v2["eventi"][1]["firma_ok"])

    def test_marca_rfc3161_input_ostile(self):
        self.assertFalse(VP.marca_temporale_rfc3161("zz", "https://example.invalid")["anchored"])
        self.assertFalse(VP.marca_temporale_rfc3161("ab" * 32, "file:///etc/passwd")["anchored"])

    @unittest.skipUnless(os.environ.get("HEALTH_TSA_URL"), "HEALTH_TSA_URL non impostata (test di rete opt-in)")
    def test_marca_rfc3161_reale(self):
        import hashlib
        d = hashlib.sha256(b"verbale di prova").hexdigest()
        m = VP.marca_temporale_rfc3161(d, os.environ["HEALTH_TSA_URL"])
        self.assertTrue(m["anchored"], m)
        senza_ca = VP.verifica_marca(m["tsr_b64"], d)
        self.assertTrue(senza_ca["firma_cms_ok"] and senza_ca["imprint_ok"] and senza_ca["granted"])
        self.assertIsNone(senza_ca["verified"])                                   # coerente, ma TSA non fidata senza CA
        self.assertFalse(VP.verifica_marca(m["tsr_b64"], "00" * 32)["verified"])   # digest diverso → NO
        import base64
        raw = bytearray(base64.b64decode(m["tsr_b64"])); raw[-40] ^= 0x01
        self.assertFalse(VP.verifica_marca(base64.b64encode(bytes(raw)).decode(), d)["firma_cms_ok"])   # token manomesso → NO


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestE2ERicezione(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_ric_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl")
        T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        T.BOARD.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = cls._orig

    def _req(self, method, path, obj=None, token=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              **({"X-Omega-Token": token} if token else {})})
        try:
            r = urllib.request.urlopen(req, timeout=10)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body.decode(errors="replace")

    def test_flusso_completo(self):
        st, out = self._req("POST", "/valuta", {"vitali": _v(rr=26, sbp=85), "eta": 70, "eta_arrivo_min": 9,
                                                 "clinica": {"gcs": 12}, "operatore": "equipaggio-7"}, self.token)
        self.assertEqual(st, 200)
        rid = out["id"]
        self.assertTrue(out["prealert"]["criteri_prealert_2025"]["pre_alert_indicato"])
        # senza token: negato
        self.assertEqual(self._req("POST", "/ricezione", {"id": rid})[0], 401)
        # valori fuori lista: 400 con problemi nominati
        st, r = self._req("POST", "/ricezione", {"id": rid, "operatore_ps": "dr-z", "ruolo": "boss",
                                                  "risposta_richiesta": "resus", "risposta_attuata": "resus"}, self.token)
        self.assertEqual(st, 400)
        self.assertTrue(r["problemi"])
        # ricezione valida con risposta alternativa motivata
        st, r = self._req("POST", "/ricezione", {"id": rid, "operatore_ps": "dr-z", "ruolo": "clinico_senior",
                                                  "risposta_richiesta": "resus",
                                                  "risposta_attuata": "revisione_senior_immediata",
                                                  "motivo_alternativa": "resus occupata"}, self.token)
        self.assertEqual(st, 200)
        self.assertTrue(r["risposta_alternativa"])
        self.assertEqual(r["audit"]["livello"], "firma-locale")
        self.assertIsNotNone(r["latenza_s"])
        # pre-alert inesistente
        self.assertEqual(self._req("POST", "/ricezione", {"id": 999, "operatore_ps": "a", "ruolo": "medico",
                                                           "risposta_richiesta": "resus", "risposta_attuata": "resus"}, self.token)[0], 404)
        # verbale: 2 eventi firmati, verificati, digest presente, nessun dato sanitario
        st, v = self._req("GET", f"/verbale/{rid}", token=self.token)
        self.assertEqual(st, 200)
        self.assertEqual(v["n_eventi"], 2)
        self.assertTrue(v["firme_tutte_verificate"])
        self.assertEqual(v["risposte_alternative"], 1)
        self.assertEqual(len(v["digest_verbale_sha256"]), 64)
        self.assertNotIn("sbp", json.dumps(v))
        # marca senza TSA configurata: dichiarato, nessuna rete
        os.environ.pop("HEALTH_TSA_URL", None)
        st, v = self._req("GET", f"/verbale/{rid}?marca=1", token=self.token)
        self.assertFalse(v["marca_temporale"]["anchored"])
        self.assertEqual(self._req("GET", f"/verbale/{rid}")[0], 401)



class TestCorrezioniCouncil(unittest.TestCase):
    """Ogni difetto trovato dal council del 13/09 ha qui il suo test: rosso sul codice di prima."""

    def test_sepsi_marcatore_ossigeno_sul_paziente_che_non_regge(self):
        # in O2 con SpO2 90 (<92): il marcatore «needs oxygen» DEVE esserci (prima era omesso)
        s = PC.sepsi_alto_rischio_jrcalc(_v(spo2=90, su_ossigeno=True), None, storia_infezione=True)
        self.assertTrue(any("Needs oxygen" in m and "below target" in m for m in s["marcatori"]))
        s2 = PC.sepsi_alto_rischio_jrcalc(_v(spo2=96, su_ossigeno=True), None, storia_infezione=True)
        self.assertTrue(any("Needs oxygen" in m for m in s2["marcatori"]))
        s3 = PC.sepsi_alto_rischio_jrcalc(_v(spo2=90, su_ossigeno=False), None, storia_infezione=True)
        self.assertFalse(any("Needs oxygen" in m for m in s3["marcatori"]))
        # BPCO: «more than 88%» → a 88 in O2 è ancora sotto target
        s4 = PC.sepsi_alto_rischio_jrcalc(_v(spo2=88, su_ossigeno=True, bpco_scala2=True), None, storia_infezione=True)
        self.assertTrue(any("below target" in m for m in s4["marcatori"]))

    def test_gcs_abituale_esclude_deficit_cronico(self):
        con = [c["criterio"] for c in PC.criteri_adulto(_v(), gcs=10, gcs_abituale=10)["criteri"]]
        self.assertNotIn("GCS", con)
        peggiore = [c["criterio"] for c in PC.criteri_adulto(_v(), gcs=9, gcs_abituale=10)["criteri"]]
        self.assertIn("GCS", peggiore)

    def test_spo2_in_aria_dichiarata_non_silenziosa(self):
        nv = PC.criteri_adulto(_v(spo2=70, su_ossigeno=False))["non_valutato"]
        self.assertTrue(any("IN ARIA" in x for x in nv))
        r = PC.criteri_pediatrici(7, dict(rr=25, hr=110, spo2=85, su_ossigeno=True))
        self.assertTrue(any("IN OSSIGENO" in x for x in r["non_valutato"]))

    def test_pediatrico_gcs_e_crt_arrivano_dal_motore(self):
        # bambino con FR/FC normali e GCS 8 (via clinica) → pre-alert indicato (prima: «nessun pre-alert»)
        v = dict(rr=22, spo2=98, su_ossigeno=False, sbp=100, hr=95, alert_coscienza=False, temp=36.8)
        out = A.valuta_paziente(v, [], 8, 10, clinica={"gcs": 8})["PRE_ALERT_INTEGRATO"]
        self.assertTrue(out["criteri_prealert_2025"]["pre_alert_indicato"])
        self.assertIn("GCS", [c["criterio"] for c in out["criteri_prealert_2025"]["criteri_fisiologici"]])
        out = A.valuta_paziente(dict(v, alert_coscienza=True), [], 8, 10, clinica={"crt_sec": 5})["PRE_ALERT_INTEGRATO"]
        self.assertTrue(out["criteri_prealert_2025"]["pre_alert_indicato"])
        out = A.valuta_paziente(dict(v, alert_coscienza=True), [], 8, 10, clinica={"crt_sec": "5"})["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_DATI_INVALIDI")

    def test_sepsi_entra_nel_motore_integrato(self):
        out = A.valuta_paziente(_v(rr=26, hr=132, sbp=88), [], 70, 10,
                                sepsi={"storia_infezione": True, "segni": {"cianosi": True}})["PRE_ALERT_INTEGRATO"]
        self.assertTrue(out["sepsi_jrcalc"]["alto_rischio"])
        self.assertIn("sepsi_alto_rischio_adulto", [c["condizione"] for c in out["criteri_prealert_2025"]["condizioni_specifiche"]])
        out = A.valuta_paziente(_v(), [], 70, 10, sepsi={"storia_infezione": "sì"})["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_DATI_INVALIDI")

    def test_condizioni_derivate_dichiarano_la_derivazione(self):
        out = A.valuta_paziente(_v(), [], 60, 10, fast_segni={"face": True})["PRE_ALERT_INTEGRATO"]
        c = [c for c in out["criteri_prealert_2025"]["condizioni_specifiche"] if c["condizione"] == "ictus_fast_positivo_in_finestra"][0]
        self.assertIn("NON è verificata", c["derivazione"])


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestVerbaleContrattacchi(unittest.TestCase):
    """Le tre falsificazioni indicate dal council: chiave estranea, cancellazione, TSR fabbricato."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="verb2_")
        self._orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(self.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(self.tmp, "keys")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = self._orig

    def _ledger(self):
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def _scrivi(self, entries):
        with open(AB.FALLBACK_LEDGER, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

    def test_riga_rifirmata_con_chiave_estranea_non_passa(self):
        import base64, hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        AB.registra_prealert("prealert-5", "ab" * 32, "equipaggio-1")
        VP.registra_ricezione("prealert-5", "dr-a", "medico", "resus", "resus")
        self.assertTrue(VP.verbale("prealert-5")["firme_tutte_verificate"])
        # l'attaccante riscrive la ricezione e la ri-firma con una chiave SUA, coerente col digest
        es = self._ledger()
        e = es[1]
        rec = {k: e[k] for k in ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256")}
        rec["dettaglio"]["risposta_attuata"] = "nessuna_risposta_specifica"
        digest = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).digest()
        sk = Ed25519PrivateKey.generate()
        e2 = {**rec, "record_sha256": digest.hex(), "firma_ed25519_b64": base64.b64encode(sk.sign(digest)).decode(),
              "pubkey_b64": base64.b64encode(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()}
        self._scrivi([es[0], e2])
        v = VP.verbale("prealert-5")
        self.assertFalse(v["firme_tutte_verificate"])
        self.assertFalse(v["eventi"][1]["firma_ok"])
        self.assertIn("registrata", v["eventi"][1]["verifica"])

    def test_cancellazione_riga_rilevata_dalla_catena(self):
        AB.registra_prealert("prealert-6", "ab" * 32, "equipaggio-1")
        VP.registra_ricezione("prealert-6", "dr-a", "clinico_senior", "resus", "revisione_senior_immediata",
                              motivo_alternativa="resus piena")
        AB.registra_conferma("prealert-6", "preso in carico", "dr-b")
        self.assertTrue(VP.verbale("prealert-6")["catena"]["catena_ok"])
        es = self._ledger()
        self._scrivi([es[0], es[2]])        # sparisce la ricezione con risposta alternativa
        v = VP.verbale("prealert-6")
        self.assertFalse(v["catena"]["catena_ok"])
        self.assertEqual(v["catena"]["rotture"][0]["riga"], 2)
        self.assertFalse(v["firme_tutte_verificate"])
        self.assertEqual(v["ricezioni"], 0)

    def test_tsr_fabbricato_non_passa(self):
        # un «token» che non è CMS: openssl non estrae né verifica → verified False, mai True
        import base64
        finto = base64.b64encode(b"Status: Granted\nMessage data:\n    0000 - " + b"ab " * 32).decode()
        r = VP.verifica_marca(finto, "ab" * 32)
        self.assertIn(r["verified"], (False, None))
        if r["verified"] is False:
            self.assertFalse(r["firma_cms_ok"])

    def test_persistenza_verbale(self):
        AB.registra_prealert("prealert-3", "ab" * 32, "equipaggio-1")
        v = VP.verbale("prealert-3")
        p = VP.persisti_verbale(v, os.path.join(self.tmp, "verbali"))
        with open(p["path"], "rb") as f:
            raw = f.read()
        import hashlib
        self.assertEqual(hashlib.sha256(raw).hexdigest(), p["sha256_file"])
        self.assertEqual(json.loads(raw)["digest_verbale_sha256"], v["digest_verbale_sha256"])
        self.assertNotIn("sbp", raw.decode())



class TestRound2(unittest.TestCase):
    """Rilievi del council round 2, ciascuno rosso sul codice precedente."""

    def test_eta_mesi_incoerente_con_eta(self):
        r = PC.criteri_pediatrici(1, dict(rr=25, hr=110, spo2=98, su_ossigeno=False, temp=39.0), 2)
        self.assertTrue(any("incoerente" in x for x in r["problemi_dati"]))
        out = A.valuta_paziente(dict(rr=25, spo2=98, su_ossigeno=False, sbp=100, hr=110, alert_coscienza=True, temp=39.0),
                                [], 1, 10, eta_mesi=2)["PRE_ALERT_INTEGRATO"]
        self.assertEqual(out["priorita"], "NON_VALUTABILE_DATI_INVALIDI")
        r = PC.criteri_pediatrici(0, dict(rr=25, hr=110, spo2=98, su_ossigeno=False), 12)
        self.assertTrue(r["problemi_dati"])

    def test_sepsi_pediatrica_non_scartata_in_silenzio(self):
        v = dict(rr=25, spo2=98, su_ossigeno=False, sbp=100, hr=110, alert_coscienza=True, temp=39.0)
        out = A.valuta_paziente(v, [], 6, 10, sepsi={"storia_infezione": True,
                                                    "segni": {"rash_non_sbiancante": True}})["PRE_ALERT_INTEGRATO"]
        self.assertTrue(any("sepsi" in x.lower() for x in out["criteri_prealert_2025"]["non_valutato"]))
        self.assertTrue(any("SEPSI PEDIATRICA" in p for p in out["percorsi_attivare"]))
        self.assertEqual(out["sepsi_jrcalc"], {"non_applicabile_pediatrico": True})

    def test_sepsi_coscienza_assente_dichiarata(self):
        s = PC.sepsi_alto_rischio_jrcalc(dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72), None, True)
        self.assertTrue(any("alert_coscienza" in x for x in s["non_valutato"]))


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestRound2Verbale(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="verb3_")
        self._orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(self.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(self.tmp, "keys")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = self._orig

    def test_chiave_legacy_senza_pub_viene_registrata(self):
        # pilota pre-13/09: esiste solo fb-<op>.key; il verbale non deve dire «senza chiave registrata»
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        os.makedirs(AB.KEYS_DIR)
        sk = Ed25519PrivateKey.generate()
        with open(os.path.join(AB.KEYS_DIR, "fb-vecchio-op.key"), "w") as f:
            f.write(base64.b64encode(sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())).decode())
        AB.registra_prealert("prealert-2", "ab" * 32, "vecchio-op")
        v = VP.verbale("prealert-2")
        self.assertTrue(v["firme_tutte_verificate"], v["eventi"])
        self.assertIn("vecchio-op", v["registro_chiavi"])

    def test_catena_al_confine_con_righe_legacy(self):
        # riga pre-13/09 (senza prev_sha256) seguita da righe nuove: fuori catena 1, catena ok
        AB.registra_prealert("prealert-4", "ab" * 32, "op")
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            e = json.loads(f.readline())
        legacy = {k: v for k, v in e.items() if k != "prev_sha256"}
        # a GENUINE legacy line has a digest over its own (prev-less) record — v0.5.0 recomputes every digest
        import hashlib as _h
        canon = json.dumps({k: legacy[k] for k in ("kind", "target", "azione", "dettaglio", "operatore", "ts", "alg")},
                           sort_keys=True, separators=(",", ":")).encode()
        legacy["record_sha256"] = _h.sha256(canon).hexdigest()
        with open(AB.FALLBACK_LEDGER, "w", encoding="utf-8") as f:
            f.write(json.dumps(legacy) + "\n")
        AB.registra_conferma("prealert-4", "ok", "op")
        v = VP.verbale("prealert-4")
        self.assertTrue(v["catena"]["catena_ok"])
        self.assertEqual(v["catena"]["righe_fuori_catena"], 1)
        self.assertFalse(v["eventi"][0]["firma_ok"])        # la riga legacy ha un digest senza prev: NON verificata come nuova
        self.assertTrue(v["eventi"][1]["firma_ok"])

    @unittest.skipUnless(os.environ.get("HEALTH_TSA_URL") and os.environ.get("HEALTH_TSA_CAFILE"), "TSA e CA reali opt-in")
    def test_fiducia_tsa_con_ca_vera_e_ca_falsa(self):
        import hashlib, tempfile as tf, subprocess
        d = hashlib.sha256(b"fiducia").hexdigest()
        m = VP.marca_temporale_rfc3161(d, os.environ["HEALTH_TSA_URL"])
        self.assertTrue(m["anchored"], m)
        senza = VP.verifica_marca(m["tsr_b64"], d)
        self.assertIsNone(senza["verified"])                       # coerente ma TSA non fidata
        self.assertEqual(senza["livello_marca"], "rfc3161-coerente-tsa-non-fidata")
        con = VP.verifica_marca(m["tsr_b64"], d, cafile=os.environ["HEALTH_TSA_CAFILE"])
        self.assertTrue(con["verified"], con)
        self.assertEqual(con["livello_marca"], "rfc3161-catena-verificata")
        fake = os.path.join(tf.mkdtemp(), "fake.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", fake + ".key",
                        "-out", fake, "-subj", "/CN=TSA-FALSA", "-days", "1"], capture_output=True, check=True)
        falsa = VP.verifica_marca(m["tsr_b64"], d, cafile=fake)
        self.assertFalse(falsa["verified"])
        self.assertFalse(falsa["catena_tsa_ok"])



@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestRound3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="verb4_")
        self._orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(self.tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(self.tmp, "keys")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = self._orig

    def test_sostituzione_con_riga_finta_legacy_rilevata(self):
        AB.registra_prealert("prealert-6", "ab" * 32, "op")
        VP.registra_ricezione("prealert-6", "dr-a", "clinico_senior", "resus", "revisione_senior_immediata",
                              motivo_alternativa="resus piena")
        AB.registra_conferma("prealert-6", "ok", "dr-b")
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            es = [json.loads(l) for l in f if l.strip()]
        finta = {"kind": "nota", "record_sha256": es[1]["record_sha256"]}      # porta l'hash della riga cancellata
        with open(AB.FALLBACK_LEDGER, "w", encoding="utf-8") as f:
            for e in (es[0], finta, es[2]):
                f.write(json.dumps(e) + "\n")
        v = VP.verbale("prealert-6")
        self.assertFalse(v["catena"]["catena_ok"])
        self.assertFalse(v["firme_tutte_verificate"])
        self.assertIn("senza prev_sha256", v["catena"]["rotture"][0]["motivo"])

    def test_operatore_con_accenti_verificato(self):
        AB.registra_prealert("prealert-7", "ab" * 32, "Dott.ssa Zoë Müller")
        v = VP.verbale("prealert-7")
        self.assertTrue(v["firme_tutte_verificate"], v["eventi"])

    def test_cafile_inesistente_e_errore_nominato(self):
        import base64
        r = VP.verifica_marca(base64.b64encode(b"non-un-token").decode(), "ab" * 32, cafile="/nonexistent/ca.pem")
        self.assertFalse(r["verified"])
        self.assertIn("HEALTH_TSA_CAFILE", r.get("errore", ""))


if __name__ == "__main__":
    unittest.main(verbosity=1)
