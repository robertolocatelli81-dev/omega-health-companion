#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Banco del fascicolo di missione — ciclo pieno, fail-closed, degrado onesto,
manomissione rilevata. Gira sia col motore privato sia senza (repo pubblico)."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import mission_case as MC  # noqa: E402

D = "ab" * 32   # digest valido di comodo


def _fm():
    tmp = tempfile.mktemp(suffix=".jsonl", prefix="fascicoli_")
    return MC.FascicoloMissione(ledger_path=tmp)


def _missione_consegnata(fm, mid="M-1"):
    fm.apri(mid, "centrale-118", "codice rosso trauma")
    fm.aggancia_atto(mid, "valutazione", D, "equipaggio-1")
    fm.transita(mid, "VALUTAZIONE", "equipaggio-1", "sul posto")
    fm.aggancia_atto(mid, "prealert", "cd" * 32, "equipaggio-1")
    fm.transita(mid, "TRASPORTO", "equipaggio-1", "verso DEA")
    fm.transita(mid, "CONSEGNATA", "equipaggio-1", "consegnato a dr-ps-notte")
    return mid


class TestCicloPieno(unittest.TestCase):
    def test_apri_atti_transizioni_pack(self):
        fm = _fm()
        mid = _missione_consegnata(fm)
        fm.transita(mid, "CHIUSA", "centrale-118", "rientro mezzo")
        self.assertTrue(fm.verifica_ledger()["ok"])
        pack = fm.fascicolo_pack(mid)
        self.assertEqual(pack["stato"], "CHIUSA")
        self.assertEqual(len(pack["atti"]), 2)
        self.assertEqual(len(pack["pack_sha256_contenuto"]), 64)
        self.assertIn(pack["livello"], ("case-engine", "fascicolo-locale"))
        json.dumps(pack)

    def test_annullamento_da_allerta(self):
        fm = _fm()
        fm.apri("M-2", "centrale-118", "sospetto ictus")
        fm.transita("M-2", "ANNULLATA", "centrale-118", "falso allarme")
        pack = fm.fascicolo_pack("M-2")
        self.assertEqual(pack["stato"], "ANNULLATA")

    def test_livello_dichiarato_coerente_col_motore(self):
        fm = _fm()
        if MC.MOTORE_DISPONIBILE:
            self.assertEqual(fm.livello(), "case-engine")
        else:
            self.assertEqual(fm.livello(), "fascicolo-locale")


class TestFailClosed(unittest.TestCase):
    def test_transizione_illegale_respinta(self):
        fm = _fm()
        fm.apri("M-3", "op", "m")
        with self.assertRaisesRegex(ValueError, "non ammessa"):
            fm.transita("M-3", "CONSEGNATA", "op", "salto stati")

    def test_consegna_senza_destinatario_respinta(self):
        fm = _fm()
        fm.apri("M-4", "op", "m")
        fm.transita("M-4", "VALUTAZIONE", "op", "x")
        fm.transita("M-4", "TRASPORTO", "op", "x")
        with self.assertRaisesRegex(ValueError, "destinatario"):
            fm.transita("M-4", "CONSEGNATA", "op", "   ")

    def test_atto_dopo_consegna_respinto(self):
        fm = _fm()
        mid = _missione_consegnata(fm, "M-5")
        with self.assertRaisesRegex(ValueError, "non piu' agganciabili"):
            fm.aggancia_atto(mid, "tardivo", D, "op")

    def test_digest_invalido_respinto(self):
        fm = _fm()
        fm.apri("M-6", "op", "m")
        for cattivo in ("", "abc", "z" * 64):
            with self.assertRaisesRegex(ValueError, "sha256"):
                fm.aggancia_atto("M-6", "valutazione", cattivo, "op")

    def test_pack_su_missione_aperta_rifiutato(self):
        fm = _fm()
        fm.apri("M-7", "op", "m")
        with self.assertRaisesRegex(ValueError, "perimetro chiuso"):
            fm.fascicolo_pack("M-7")

    def test_doppia_apertura_respinta(self):
        fm = _fm()
        fm.apri("M-8", "op", "m")
        with self.assertRaisesRegex(ValueError, "gia' aperta"):
            fm.apri("M-8", "op2", "m2")

    def test_missione_sconosciuta(self):
        fm = _fm()
        with self.assertRaises(KeyError):
            fm.transita("fantasma", "VALUTAZIONE", "op", "x")

    def test_manomissione_ledger_rilevata_e_pack_rifiutato(self):
        fm = _fm()
        mid = _missione_consegnata(fm, "M-9")
        righe = open(fm.ledger_path).read().splitlines()
        r0 = json.loads(righe[1])
        r0["sha256"] = "ee" * 32           # scambio dell'atto dopo la messa in catena
        righe[1] = json.dumps(r0, ensure_ascii=False)
        open(fm.ledger_path, "w").write("\n".join(righe) + "\n")
        v = fm.verifica_ledger()
        self.assertFalse(v["ok"])
        with self.assertRaisesRegex(ValueError, "NON verificata"):
            fm.fascicolo_pack(mid)

    def test_stati_terminali_immutabili(self):
        fm = _fm()
        fm.apri("M-10", "op", "m")
        fm.transita("M-10", "ANNULLATA", "op", "revoca")
        with self.assertRaises(ValueError):
            fm.transita("M-10", "VALUTAZIONE", "op", "riprovo")


class TestColpiPro(unittest.TestCase):
    def test_truncation_exploit_respinto(self):
        # 200 spazi + destinatario: la validazione avviene sulla nota TAGLIATA
        fm = _fm()
        fm.apri("M-20", "op", "m")
        fm.transita("M-20", "VALUTAZIONE", "op", "x")
        fm.transita("M-20", "TRASPORTO", "op", "x")
        with self.assertRaisesRegex(ValueError, "destinatario"):
            fm.transita("M-20", "CONSEGNATA", "op", " " * 200 + "dr-ps")

    def test_orologio_indietro_rifiutato(self):
        fm = _fm()
        fm.apri("M-21", "op", "m")
        vero = MC._utc
        MC._utc = lambda: "2020-01-01T00:00:00+00:00"
        try:
            with self.assertRaisesRegex(ValueError, "orologio"):
                fm.transita("M-21", "VALUTAZIONE", "op", "x")
        finally:
            MC._utc = vero
        # e il ledger e' rimasto INTEGRO (l'evento non e' entrato)
        self.assertTrue(fm.verifica_ledger()["ok"])
        fm.transita("M-21", "VALUTAZIONE", "op", "ora giusta")

    def test_append_concorrente_non_forca_la_catena(self):
        # 20 thread agganciano atti insieme: col lock la catena resta UNA
        import threading
        fm = _fm()
        fm.apri("M-22", "op", "m")
        errori = []

        def atto(i):
            try:
                fm.aggancia_atto("M-22", f"t{i}", D, "op")
            except Exception as e:  # noqa: BLE001
                errori.append(e)

        ts = [threading.Thread(target=atto, args=(i,)) for i in range(20)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errori, [])
        v = fm.verifica_ledger()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["righe"], 21)


class TestMultiProcesso(unittest.TestCase):
    def test_replay_su_istanza_nuova(self):
        # un ALTRO processo (istanza nuova sullo stesso ledger) continua la missione
        fm1 = _fm()
        fm1.apri("M-11", "op", "m")
        fm1.transita("M-11", "VALUTAZIONE", "op", "x")
        fm2 = MC.FascicoloMissione(ledger_path=fm1.ledger_path)
        fm2.transita("M-11", "TRASPORTO", "op", "x")
        fm2.transita("M-11", "CONSEGNATA", "op", "a dr-ps")
        pack = fm2.fascicolo_pack("M-11")
        self.assertEqual(pack["stato"], "CONSEGNATA")

    def test_tabella_fsm_esaustiva(self):
        raggiungibili = {s for d in MC.TRANSIZIONI.values() for s in d}
        for s in raggiungibili:
            self.assertIn(s, MC.TRANSIZIONI)


if __name__ == "__main__":
    unittest.main(verbosity=2)
