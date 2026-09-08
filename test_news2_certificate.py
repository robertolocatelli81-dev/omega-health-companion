# -*- coding: utf-8 -*-
"""Test del certificato di concordanza NEWS2 (giudice indipendente, 08/09)."""
import unittest

import news2_certificate as nc


class TestNews2Certificate(unittest.TestCase):
    def test_certificato_ok(self):
        r = nc.certifica()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["disaccordi"], 0)
        self.assertGreater(r["vettori"], 500)

    def test_banco_sa_fallire(self):
        rotta = dict(nc._TABELLA)
        rotta["hr"] = [(40, 3), (50, 1), (91, 0), (110, 1), (130, 2),
                       (float("inf"), 3)]           # bordo hr 90->91
        ok_finto, det = nc._concordanza(rotta)
        self.assertFalse(ok_finto)                  # DEVE vederla

    def test_bordi_esatti_rcp(self):
        # bordi noti: spo2 95->1, 96->0; sbp 219->0, 220->3; hr 90->0, 91->1
        g = nc.news2_indipendente(15, 95, False, 120, 70, True, 37.0)
        self.assertEqual(g["comp"]["spo2"], 1)
        g = nc.news2_indipendente(15, 96, False, 220, 91, True, 37.0)
        self.assertEqual(g["comp"]["spo2"], 0)
        self.assertEqual(g["comp"]["sbp"], 3)
        self.assertEqual(g["comp"]["hr"], 1)

    def test_scope_dichiarato(self):
        r = nc.certifica()
        self.assertIn("deviazione DICHIARATA", r["scope"])
        self.assertIn("Scala 2 BPCO fuori scope", r["scope"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
