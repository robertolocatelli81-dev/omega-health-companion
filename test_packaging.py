#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Il wheel deve contenere OGNI modulo del prodotto (13/09/2026: la 0.4.0 su pip era senza prealert_criteria,
verbale_probatorio, coordinamento e news2_certificate — pyproject elenca i moduli a mano). Rosso sulla 0.4.0."""
import os, re, unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


class TestPackaging(unittest.TestCase):
    def test_ogni_modulo_del_prodotto_e_nel_wheel(self):
        with open(os.path.join(_HERE, "pyproject.toml")) as f:
            m = re.search(r"py-modules\s*=\s*\[(.*?)\]", f.read(), re.S)
        elencati = set(re.findall(r"'([a-z0-9_]+)'", m.group(1)))
        sul_disco = {n[:-3] for n in os.listdir(_HERE) if n.endswith(".py") and not n.startswith("test_") and n != "demo.py"}
        self.assertEqual(sul_disco - elencati, set(), f"moduli non impacchettati: {sorted(sul_disco - elencati)}")
        self.assertEqual(elencati - sul_disco, set(), f"moduli elencati ma assenti: {sorted(elencati - sul_disco)}")


if __name__ == "__main__":
    unittest.main()
