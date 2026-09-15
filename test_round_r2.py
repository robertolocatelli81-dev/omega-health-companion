#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Council round 2 (15/09/2026, five models): each test was red on v0.5.0 as first pushed, green after the fix."""
import json, os, shutil, sys, tempfile, unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_bridge as AB
import scores_emergenza as S
import mission_case as MC
import coordinamento as CO
import barella_prealert as B
import verbale_probatorio as VP
import team_comms as T


HAVE_CRYPTO = AB.FIRMA_LOCALE_DISPONIBILE


class TestRound2(unittest.TestCase):
    def setUp(self):
        self.saved = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER)
        self.d = tempfile.mkdtemp(prefix="r2_")
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(self.d, "audit.jsonl"); AB.KEYS_DIR = os.path.join(self.d, "keys"); os.makedirs(AB.KEYS_DIR)
        S.LEDGER = os.path.join(self.d, "prealert.jsonl")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER = self.saved
        shutil.rmtree(self.d, ignore_errors=True)

    def test_acr_contradictory_input_declared(self):
        r = S.acr(assenza_respiro=False, assenza_polso=True, coscienza_assente=False)
        self.assertFalse(r["arresto"]); self.assertTrue(r["dati_contraddittori"]); self.assertIn("CONTRADDITTORI", r["azione"])
        self.assertTrue(S.acr(True, True, True)["arresto"]); self.assertTrue(S.acr(False, True, True)["arresto"])   # gasping, no pulse, unresponsive

    def test_anchor_lock_released_on_error(self):
        os.makedirs(S.LEDGER, exist_ok=True)          # the ledger path is a DIRECTORY: append must fail
        r = S.ancora_prealert({"x": 1}, "2026-09-15T08:00:00+00:00")
        self.assertFalse(r["ancorato"])
        shutil.rmtree(S.LEDGER)
        self.assertTrue(S.ancora_prealert({"x": 1}, "2026-09-15T08:00:00+00:00")["ancorato"])   # lock was released

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente: nessun record firmato da cui ripartire")
    def test_prealert_id_continues_after_restart(self):
        AB.registra_prealert("prealert-7", "ab" * 32, "op")
        T._BOARD_SEQ[0] = 0                          # "restart"
        self.assertEqual(AB.ultimo_id_prealert(), 7)

    def test_mission_apri_validates_before_engine(self):
        fm = MC.FascicoloMissione(ledger_path=os.path.join(self.d, "f.jsonl"))
        with self.assertRaises(ValueError):
            fm.apri("M1", "op", "x" * 201)
        fm.apri("M1", "op", "ok")                    # no stale in-memory case blocks the retry
        self.assertEqual(fm._stato("M1")["stato"], "ALLERTA")

    def test_position_rounding_half_away_from_zero(self):
        self.assertEqual(CO._e6(0.0000005), 1); self.assertEqual(CO._e6(-0.0000005), -1); self.assertEqual(CO._e6(45.1234565), 45123457)
        self.assertEqual(CO.posizione_testo(45.5, -9.25), "45500000,-9250000")

    def test_prealert_age_bounds(self):
        with self.assertRaises(ValueError):
            B.prealert(10 ** 9, {"rr": 16, "spo2": 97, "su_ossigeno": False, "sbp": 120, "hr": 80, "alert_coscienza": True, "temp": 37.0}, 5)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_verbale_temporal_anomaly_declared(self):
        AB.registra_prealert("prealert-3", "ab" * 32, "eq")
        VP.registra_ricezione("prealert-3", "dr", "clinico_senior", "resus", "resus")
        lines = [json.loads(l) for l in open(AB.FALLBACK_LEDGER) if l.strip()]
        # backdate the signed emission? no — forge nothing: move the RECEIPT's ts before the emission by re-signing is not
        # possible for a third party; here we simulate a clock skew by rewriting the receipt ts and re-signing with its own key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64, hashlib
        e = lines[1]; e["ts"] = "2020-01-01T00:00:00+00:00"
        keys = ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg")
        dg = hashlib.sha256(json.dumps({k: e[k] for k in keys if k in e}, sort_keys=True, separators=(",", ":")).encode()).digest()
        sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(open(os.path.join(AB.KEYS_DIR, "fb-dr.key")).read().strip()))
        e["record_sha256"] = dg.hex(); e["firma_ed25519_b64"] = base64.b64encode(sk.sign(dg)).decode()
        open(AB.FALLBACK_LEDGER, "w").write("\n".join(json.dumps(x, ensure_ascii=False) for x in lines) + "\n")
        v = VP.verbale("prealert-3")
        self.assertEqual(len(v["anomalie_temporali"]), 1); self.assertIsNone(v["latenza_emissione_ricezione_ms"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
