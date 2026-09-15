#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""health_verify.py (the third-party verifier) on sandboxed fixtures: intact → PASS with a registry, NOT-TRUSTED
without; every tamper the oracle builds → FAIL. Canonical parity with json.dumps on accents, floats kept as text,
big integers, microsecond timestamps. Never touches the repository's real ledgers."""
import json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifiers"))
import audit_bridge as AB
import scores_emergenza as S
import health_verify as HV
import differential as D


try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


class TestHealthVerify(unittest.TestCase):
    def setUp(self):
        self.saved = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER)
        self.base = tempfile.mkdtemp(prefix="hv_")

    def tearDown(self):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER = self.saved
        shutil.rmtree(self.base, ignore_errors=True)

    def test_canonical_parity_with_json_dumps(self):
        objs = [{"a": 1, "z": "già ≤ 2 — «x»", "n": [1.0, 2.5, 1e-05, 1e+16, 12345678901234567890, -0.0], "u": " <&>", "k": None, "b": True}]
        for o in objs:
            for asc in (True, False):
                ref = json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=asc)
                self.assertEqual(HV.canonical(HV.loads(ref), asc).decode(), ref)

    def test_strict_parse(self):
        with self.assertRaises(ValueError):
            HV.loads('{"a": 1, "a": 2}')
        with self.assertRaises(ValueError):
            HV.loads('{"a": NaN}')
        self.assertEqual(HV.loads('{"x": 39.0}')["x"].text, "39.0")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente: le fixture firmate non si producono (livello base)")
    def test_every_oracle_case_has_the_expected_verdict(self):
        expected_pass = {"intact_with_registry", "intact_registry_from_verbale", "intact_rewritten_lines"}
        not_trusted = {"intact_no_registry", "honest_verbale_no_registry", "verbale_claim_no_registry"}   # unverifiable ≠ false (council r2)
        for name, f, opts in D.cases(self.base):
            r = HV.run(f["audit"], f["chains"], f["verbale"], f["keys"] if opts.get("keys") else None, bool(opts.get("trust_vr")))
            self.assertEqual(r["ok"], name in expected_pass, (name, r["layers"]))
            if name in not_trusted:
                self.assertEqual(r["verdict"], "NOT-TRUSTED", (name, r["layers"]))
            elif name in expected_pass:
                self.assertEqual(r["verdict"], "PASS")
            else:
                self.assertEqual(r["verdict"], "FAIL", (name, r["layers"]))

    def test_integer_lexeme_kept(self):
        self.assertEqual(HV.canonical(HV.loads('{"n": -0, "m": 7}'), True).decode(), '{"m":7,"n":-0}')


if __name__ == "__main__":
    unittest.main(verbosity=1)
