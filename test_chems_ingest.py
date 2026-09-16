#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CH EMS reader + evidence layer: positive path on the exporter's own documents, null controls (a document that is
not a document, dangling reference, duplicate keys, wrong units), scoring honesty (no age → not scored, never
guessed) and the evidence record verified by the reference verifier on a sandboxed ledger."""
import json
import os
import shutil
import tempfile
import unittest

import chems_ingest as I
import fhir_chems as C

SAMPLE = "examples/chems_document_sample.json"
MINIMAL = "examples/chems_document_sample_minimal.json"


class TestChemsIngest(unittest.TestCase):
    def test_read_and_extract(self):
        doc = I.leggi_documento(SAMPLE)
        self.assertEqual(doc["per_tipo"]["Observation"], 12); self.assertEqual(doc["avvisi"], []); self.assertEqual(len(doc["bytes_sha256"]), 64)
        ex = I.estrai_vitali(doc)
        self.assertEqual(ex["vitali"], {"rr": 28.0, "hr": 135.0, "sbp": 85.0, "spo2": 89.0, "temp": 39.4, "alert_coscienza": True, "avpu": "A"})
        self.assertEqual(ex["mancanti"], []); self.assertEqual(ex["problemi"], [])
        self.assertEqual(ex["missione"], {"numero": "ZH-2026-000123", "sistema": "urn:oid:2.16.756.5.30.1.999.1", "evento": "42"})
        self.assertEqual(ex["colore"], "rosso"); self.assertEqual(sorted(ex["tempi"]), ["allarme", "arrivo_paziente", "arrivo_sul_posto", "partenza", "partenza_dal_posto"])
        self.assertIsNone(ex["eta"]); self.assertEqual(ex["stato_documento"], "preliminary")
        exm = I.estrai_vitali(I.leggi_documento(MINIMAL))
        self.assertEqual(exm["vitali"], {"hr": 135.0}); self.assertIn("alert_coscienza", exm["mancanti"]); self.assertIsNone(exm["colore"])

    def test_scoring_is_honest_about_missing_inputs(self):
        doc = I.leggi_documento(SAMPLE)
        v = I.valuta_documento(doc, 8)
        self.assertFalse(v["valutabile"]); self.assertIn("età assente", v["motivo_non_valutabile"])
        v = I.valuta_documento(doc, 8, eta=67)
        self.assertTrue(v["valutabile"]); self.assertEqual(v["PRE_ALERT_INTEGRATO"]["priorita"], "ALTO"); self.assertEqual(v["PRE_ALERT_INTEGRATO"]["NEWS2"], 14)
        self.assertTrue(any("su_ossigeno=False" in a for a in v["assunzioni"])); self.assertNotIn("avpu", v["vitali_usati"])
        # a document that carries a birthDate is aged from Composition.date, not from today (no wall clock)
        b = json.load(open(SAMPLE)); pat = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Patient"); pat["birthDate"] = "1959-03-02"
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["eta"], 67)

    def test_null_controls_refuse(self):
        raw = open(SAMPLE, "rb").read()
        with self.assertRaises(I.DocumentoNonValido):
            I.leggi_documento(raw.replace(b'"type": "document"', b'"type": "document", "type": "collection"', 1))      # duplicate key
        for mut in (lambda b: b.update(type="collection"), lambda b: b["entry"].pop(0),
                    lambda b: b["entry"][4]["resource"].__setitem__("subject", {"reference": "urn:uuid:00000000-0000-0000-0000-000000000009"}),
                    lambda b: b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-000000000001", "resource": {"resourceType": "Observation", "id": "o", "status": "final", "code": {"text": "x"}}}),
                    lambda b: b["entry"][5]["resource"].__setitem__("requester", {"reference": "#nessuno"})):
            b = json.loads(raw); mut(b)
            with self.assertRaises(I.DocumentoNonValido):
                I.leggi_documento(b)
        b = json.loads(raw); b["entry"].append(json.loads(json.dumps(b["entry"][3])))              # duplicate fullUrl (council r10 coverage)
        with self.assertRaises(I.DocumentoNonValido):
            I.leggi_documento(b)
        # wrong unit: refused and SAID, never converted
        b = json.loads(raw); hr = next(e["resource"] for e in b["entry"] if e["resource"]["id"] == "vit-hr"); hr["valueQuantity"]["code"] = "bpm"; hr["valueQuantity"]["unit"] = "bpm"
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("hr", ex["vitali"]); self.assertTrue(any("frequenza cardiaca" in p for p in ex["problemi"]))
        # V/P/U → not alert; GCS-only → derived and declared
        b = json.loads(raw); av = next(e["resource"] for e in b["entry"] if e["resource"]["id"] == "vit-avpu"); av["valueCodeableConcept"]["coding"][0]["code"] = "P"
        self.assertFalse(I.estrai_vitali(I.leggi_documento(b))["vitali"]["alert_coscienza"])

    def test_real_ig_examples_are_read(self):
        """The IG's own published documents (package copy; the online files are semantically identical — measured
        16/09): absolute RESTful fullUrls with RELATIVE references, identified and unidentified patients."""
        base = os.path.expanduser("~/.fhir/packages/ch.fhir.ig.ch-ems#2.0.0-ballot/package/example")
        if not os.path.isdir(base):
            self.skipTest("CH EMS package not downloaded")
        doc = I.leggi_documento(os.path.join(base, "Bundle-1-Einsatzprotokoll.json"))
        ex = I.estrai_vitali(doc)
        self.assertEqual(ex["eta"], 55); self.assertEqual(ex["gcs"], 15); self.assertEqual(ex["naca"], "III"); self.assertEqual(ex["missione"]["numero"], "S12345678")
        self.assertEqual(ex["vitali"], {"sbp": 120.0, "alert_coscienza": True}); self.assertEqual(len(ex["tempi"]), 6)
        v = I.valuta_documento(doc); self.assertFalse(v["valutabile"]); self.assertIn("vitali NEWS2 mancanti", v["motivo_non_valutabile"])
        doc2 = I.estrai_vitali(I.leggi_documento(os.path.join(base, "Bundle-2-Einsatzprotokoll.json")))
        self.assertIsNone(doc2["eta"]); self.assertEqual(doc2["vitali"], {"alert_coscienza": False, "avpu": "V"}); self.assertEqual(doc2["gcs"], 10)
        # a relative reference from a urn:uuid fullUrl is NOT resolvable (spec), an absolute one must match exactly
        b = json.load(open(os.path.join(base, "Bundle-1-Einsatzprotokoll.json")))
        b["entry"][0]["fullUrl"] = "urn:uuid:3b2d3c1e-0000-4000-8000-000000000001"
        with self.assertRaises(I.DocumentoNonValido):
            I.leggi_documento(b)

    def test_council_r2_semantics(self):
        """Quantity without UCUM system or with a comparator refused; observations of another subject ignored and said;
        duplicates ordered by AWARE instant; GCS unit not tautological; no consciousness assumed; partial birthDate."""
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        b = json.loads(raw); del obs(b, "vit-hr")["valueQuantity"]["system"]
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("hr", ex["vitali"]); self.assertTrue(any("senza system UCUM" in p for p in ex["problemi"]))
        b = json.loads(raw); obs(b, "vit-hr")["valueQuantity"]["comparator"] = "<"
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("hr", ex["vitali"]); self.assertTrue(any("comparatore" in p for p in ex["problemi"]))
        # a second heart rate for ANOTHER patient (reachable through the annotation section) must not be merged
        b = json.loads(raw)
        other = {"resourceType": "Patient", "id": "altro", "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">x</div>"}}
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000a", "resource": other})
        hr2 = json.loads(json.dumps(obs(b, "vit-hr"))); hr2["id"] = "vit-hr-altro"; hr2["subject"] = {"reference": "urn:uuid:00000000-0000-0000-0000-00000000000a"}
        hr2["valueQuantity"]["value"] = 40; hr2["effectiveDateTime"] = "2026-09-16T11:00:00+02:00"
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000b", "resource": hr2})
        ann = b["entry"][0]["resource"]["section"][-1]; ann["entry"] += [{"reference": "urn:uuid:00000000-0000-0000-0000-00000000000b"}, {"reference": "urn:uuid:00000000-0000-0000-0000-00000000000a"}]
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["vitali"]["hr"], 135.0); self.assertTrue(any("non attribuite" in p for p in ex["problemi"]))
        # duplicates for the SAME patient: 08:30Z is LATER than 10:00+02:00 → the Z one wins, and the duplicate is reported
        b = json.loads(raw); hr2 = json.loads(json.dumps(obs(b, "vit-hr"))); hr2["id"] = "vit-hr-2"; hr2["valueQuantity"]["value"] = 60
        hr2["effectiveDateTime"] = "2026-09-16T08:30:00Z"; obs(b, "vit-hr")["effectiveDateTime"] = "2026-09-16T10:00:00+02:00"
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000c", "resource": hr2}); b["entry"][0]["resource"]["section"][-1]["entry"].append({"reference": "urn:uuid:00000000-0000-0000-0000-00000000000c"})
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["vitali"]["hr"], 60.0); self.assertTrue(any("tenuta vit-hr-2" in p for p in ex["problemi"]))
        # an undated duplicate never overrides a dated one
        b = json.loads(raw); hr2 = json.loads(json.dumps(obs(b, "vit-hr"))); hr2["id"] = "vit-hr-3"; hr2["valueQuantity"]["value"] = 60; del hr2["effectiveDateTime"]
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000d", "resource": hr2}); b["entry"][0]["resource"]["section"][-1]["entry"].append({"reference": "urn:uuid:00000000-0000-0000-0000-00000000000d"})
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["vitali"]["hr"], 135.0)
        # GCS in kilograms is refused; GCS as valueInteger accepted; no AVPU/GCS → not scorable, never assumed alert
        b = json.loads(raw); av = obs(b, "vit-avpu"); av["code"] = {"coding": [{"system": "http://loinc.org", "code": "9269-2"}]}; del av["valueCodeableConcept"]
        av["valueQuantity"] = {"value": 9, "unit": "kg", "system": "http://unitsofmeasure.org", "code": "kg"}
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertIsNone(ex["gcs"]); self.assertNotIn("alert_coscienza", ex["vitali"])
        self.assertFalse(I.valuta_documento(I.leggi_documento(b), 8, eta=67)["valutabile"]); self.assertIn("coscienza assente", I.valuta_documento(I.leggi_documento(b), 8, eta=67)["motivo_non_valutabile"])
        av["valueQuantity"] = None; av["valueInteger"] = 12
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["gcs"], 12)
        # partial birthDate
        b = json.loads(raw); pat = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Patient"); pat["birthDate"] = "1990-05"
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["eta"], 36); self.assertTrue(any("anno-mese" in a for a in ex["assunzioni"]))
        v = I.valuta_documento(I.leggi_documento(SAMPLE), 8, eta=67); self.assertTrue(v["news2_limite_inferiore"])

    def test_council_r3_semantics(self):
        """A newer but malformed observation empties the slot (never the stale older value); date-only effectives are
        not ordering instants; every blocking reason is reported, none overwritten."""
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        b = json.loads(raw); hr2 = json.loads(json.dumps(obs(b, "vit-hr"))); hr2["id"] = "vit-hr-new"; hr2["valueQuantity"]["comparator"] = "<"; hr2["valueQuantity"]["value"] = 40
        hr2["effectiveDateTime"] = "2026-09-16T11:00:00+02:00"
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000e", "resource": hr2}); b["entry"][0]["resource"]["section"][-1]["entry"].append({"reference": "urn:uuid:00000000-0000-0000-0000-00000000000e"})
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("hr", ex["vitali"]); self.assertIn("hr", ex["mancanti"])
        b = json.loads(raw); hr2 = json.loads(json.dumps(obs(b, "vit-hr"))); hr2["id"] = "vit-hr-date"; hr2["valueQuantity"]["value"] = 60; hr2["effectiveDateTime"] = "2026-09-17"
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-00000000000f", "resource": hr2}); b["entry"][0]["resource"]["section"][-1]["entry"].append({"reference": "urn:uuid:00000000-0000-0000-0000-00000000000f"})
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["vitali"]["hr"], 135.0); self.assertTrue(any("data senza ora" in p for p in ex["problemi"]))
        b = json.loads(raw); b["entry"] = [e for e in b["entry"] if e["resource"]["id"] != "vit-avpu"]
        b["entry"][0]["resource"]["section"][1]["section"] = [s for s in b["entry"][0]["resource"]["section"][1]["section"] if s["title"] != "Disability"]
        v = I.valuta_documento(I.leggi_documento(b), 8)
        self.assertIn("coscienza assente", v["motivo_non_valutabile"]); self.assertIn("età assente", v["motivo_non_valutabile"])

    def test_council_r5_order_independence(self):
        """Same-code duplicates are resolved on the SET: every permutation of the Bundle gives the same result.
        Mixed (two undated + one dated) → the dated one; two undated only → none; tie on the instant → none;
        the chosen one malformed → none (never a stale value); effectiveInstant counts as a dated instant."""
        import itertools
        raw = open(SAMPLE, "rb").read()
        def mk(rid, value, eff=None, inst=None, comparator=None):
            b = json.loads(raw); o = json.loads(json.dumps(next(e["resource"] for e in b["entry"] if e["resource"]["id"] == "vit-hr")))
            o["id"] = rid; o["valueQuantity"]["value"] = value; o.pop("effectiveDateTime", None)
            if eff: o["effectiveDateTime"] = eff
            if inst: o["effectiveInstant"] = inst
            if comparator: o["valueQuantity"]["comparator"] = comparator
            return o
        def doc_with(observations):
            b = json.loads(raw); hr_url = next(e["fullUrl"] for e in b["entry"] if e["resource"]["id"] == "vit-hr")
            b["entry"] = [e for e in b["entry"] if e["resource"]["id"] != "vit-hr"]
            for e in b["entry"]:                                                    # drop references to the removed HR
                r = e["resource"]
                if r["resourceType"] == "RiskAssessment": r["basis"] = [x for x in r["basis"] if x["reference"] != hr_url]
            comp = b["entry"][0]["resource"]
            for sec in comp["section"]:
                for sub in sec.get("section", []): sub["entry"] = [x for x in sub.get("entry", []) if x["reference"] != hr_url]
                sec["entry"] = [x for x in sec.get("entry", []) if x["reference"] != hr_url]
            for k, o in enumerate(observations):
                u = f"urn:uuid:00000000-0000-0000-0000-0000000000{20 + k:02x}"
                b["entry"].append({"fullUrl": u, "resource": o}); comp["section"][-1]["entry"].append({"reference": u})
            return b
        cases = [
            ([mk("A", 60, eff="2026-09-16"), mk("B", 135, eff="2026-09-16"), mk("Cd", 90, eff="2026-09-16T11:00:00+02:00")], 90.0),
            ([mk("A", 60, eff="2026-09-16"), mk("B", 135, eff="2026-09-16")], None),
            ([mk("A", 60, eff="2026-09-16T11:00:00+02:00"), mk("B", 135, eff="2026-09-16T09:00:00Z")], None),      # same instant
            ([mk("A", 60, eff="2026-09-16T10:00:00+02:00"), mk("B", 40, eff="2026-09-16T11:00:00+02:00", comparator="<")], None),
            ([mk("A", 60, eff="2026-09-16T10:00:00+02:00"), mk("B", 70, inst="2026-09-16T12:00:00+02:00")], 70.0),
        ]
        for observations, expected in cases:
            for perm in itertools.permutations(observations):
                ex = I.estrai_vitali(I.leggi_documento(doc_with(list(perm))))
                self.assertEqual(ex["vitali"].get("hr"), expected, f"{[o['id'] for o in perm]} → {ex['vitali'].get('hr')} | {ex['problemi']}")

    def test_council_r6_codings_and_status(self):
        """An unmapped coding placed before the valid one does not lose the value; `corrected` is a valid status;
        `problemi` is deterministic under Bundle reversal."""
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        b = json.loads(raw); pr = obs(b, "priorita-paziente"); pr["valueCodeableConcept"]["coding"].insert(0, {"system": "http://snomed.info/sct", "code": "999999"})
        av = obs(b, "vit-avpu"); av["valueCodeableConcept"]["coding"].insert(0, {"system": C.CS_IVR, "code": "X"})
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["colore"], "rosso"); self.assertEqual(ex["vitali"]["avpu"], "A")
        b = json.loads(raw); obs(b, "vit-hr")["status"] = "corrected"
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["vitali"]["hr"], 135.0)
        b = json.loads(raw); obs(b, "vit-hr")["status"] = "entered-in-error"
        self.assertNotIn("hr", I.estrai_vitali(I.leggi_documento(b))["vitali"])
        b = json.loads(raw); b["entry"] = [b["entry"][0]] + b["entry"][1:][::-1]
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["problemi"], I.estrai_vitali(I.leggi_documento(SAMPLE))["problemi"])

    def test_council_r7_no_positional_fallbacks(self):
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        # two Encounters and no Composition.encounter → mission number not attributable, whatever the order
        for reverse in (False, True):
            b = json.loads(raw); comp = b["entry"][0]["resource"]; comp.pop("encounter", None)
            e2 = json.loads(json.dumps(obs(b, "missione"))); e2["id"] = "missione-altra"; e2["identifier"][0]["value"] = "MISSIONE-ALTRA"
            entry = {"fullUrl": "urn:uuid:00000000-0000-0000-0000-000000000030", "resource": e2}; comp["section"][0]["entry"].append({"reference": entry["fullUrl"]})
            b["entry"].insert(1, entry) if reverse else b["entry"].append(entry)
            ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("numero", ex["missione"]); self.assertTrue(any("non attribuibile" in p for p in ex["problemi"]))
        b = json.loads(raw); b["entry"][0]["resource"].pop("encounter", None)
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["missione"]["numero"], "ZH-2026-000123")   # unique Encounter: fine
        # two systolic components → no value; arrest non-boolean → said; mission time without valueDateTime → said
        b = json.loads(raw); bp = obs(b, "vit-sbp"); bp["component"].append(json.loads(json.dumps(bp["component"][0]))); bp["component"][-1]["valueQuantity"]["value"] = 999
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("sbp", ex["vitali"]); self.assertTrue(any("componenti sistoliche" in p for p in ex["problemi"]))
        b = json.loads(raw); tm = obs(b, "tempo-allarme"); del tm["valueDateTime"]; tm["valueString"] = "x"
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("allarme", ex["tempi"]); self.assertTrue(any("senza valueDateTime" in p for p in ex["problemi"]))

    def test_council_r8_mission_attribution(self):
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        # Composition.encounter pointing at the Patient: no number, said (no fallback to the unique Encounter)
        b = json.loads(raw); comp = b["entry"][0]["resource"]; comp["encounter"] = dict(comp["subject"])
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("numero", ex["missione"]); self.assertTrue(any("non risolve a un Encounter" in p for p in ex["problemi"]))
        # two different MN identifiers, either order → no number; the same MN twice → fine
        for reverse in (False, True):
            b = json.loads(raw); enc = obs(b, "missione"); other = json.loads(json.dumps(enc["identifier"][0])); other["value"] = "ZH-2026-999999"
            enc["identifier"] = [other, enc["identifier"][0], enc["identifier"][1]] if reverse else [enc["identifier"][0], other, enc["identifier"][1]]
            ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("numero", ex["missione"]); self.assertEqual(ex["missione"]["evento"], "42"); self.assertTrue(any("identificatori MN" in p for p in ex["problemi"]))
        b = json.loads(raw); enc = obs(b, "missione"); enc["identifier"].append(json.loads(json.dumps(enc["identifier"][0])))
        self.assertEqual(I.estrai_vitali(I.leggi_documento(b))["missione"]["numero"], "ZH-2026-000123")

    def test_council_r9_encounter_subject_and_identifier_values(self):
        raw = open(SAMPLE, "rb").read()
        def obs(b, rid): return next(e["resource"] for e in b["entry"] if e["resource"]["id"] == rid)
        # the Encounter of another patient (reachable) attributes nothing, with or without Composition.encounter
        for drop_ref in (False, True):
            b = json.loads(raw); other = {"resourceType": "Patient", "id": "altro", "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">x</div>"}}
            b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-000000000040", "resource": other}); b["entry"][0]["resource"]["section"][-1]["entry"].append({"reference": "urn:uuid:00000000-0000-0000-0000-000000000040"})
            obs(b, "missione")["subject"] = {"reference": "urn:uuid:00000000-0000-0000-0000-000000000040"}
            if drop_ref: b["entry"][0]["resource"].pop("encounter")
            ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("numero", ex["missione"]); self.assertTrue(any("Encounter.subject" in p for p in ex["problemi"]))
        # identifiers without value are unusable and said; EVENT conflicts by (system, value)
        b = json.loads(raw); enc = obs(b, "missione"); del enc["identifier"][0]["value"]; del enc["identifier"][1]["value"]
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertEqual(ex["missione"], {}); self.assertEqual(sum("senza value" in p for p in ex["problemi"]), 2)
        b = json.loads(raw); enc = obs(b, "missione"); e2 = json.loads(json.dumps(enc["identifier"][1])); e2["system"] = "https://altro.example/incident"; enc["identifier"].append(e2)
        ex = I.estrai_vitali(I.leggi_documento(b)); self.assertNotIn("evento", ex["missione"]); self.assertEqual(ex["missione"]["numero"], "ZH-2026-000123")

    def test_evidence_record_verifies_offline(self):
        import audit_bridge as AB
        import health_verify as HV
        if not AB.FIRMA_LOCALE_DISPONIBILE:
            self.skipTest("cryptography absent: no local signature")
        tmp = tempfile.mkdtemp()
        old = (AB.FALLBACK_LEDGER, AB.KEYS_DIR, AB.MOTORE_DISPONIBILE)
        try:
            AB.FALLBACK_LEDGER, AB.KEYS_DIR, AB.MOTORE_DISPONIBILE = os.path.join(tmp, "ledger.jsonl"), os.path.join(tmp, "keys"), False
            os.makedirs(AB.KEYS_DIR)
            a = I.ancora_documento(SAMPLE, "triage-ps-01", {"ran": True, "errors": [], "warnings": [1] * 8})
            self.assertEqual(a["digest_di"], "bytes"); self.assertTrue(a["audit"]["firma_verificata"])
            line = json.loads(open(AB.FALLBACK_LEDGER).read().splitlines()[-1])
            self.assertEqual(line["dettaglio"]["doc_sha256"], a["doc_sha256"]); self.assertEqual(line["dettaglio"]["validator_errori"], 0)
            self.assertNotIn("135", json.dumps(line["dettaglio"]))                                     # no clinical data in the ledger
            r = HV.run(AB.FALLBACK_LEDGER, [], None, AB.KEYS_DIR, False)
            self.assertEqual(r["verdict"], "PASS")
            # a tampered document has another digest → the anchored one no longer matches
            raw = open(SAMPLE, "rb").read().replace(b'"value": 135.0', b'"value": 35.0')
            self.assertNotEqual(I.leggi_documento(raw)["bytes_sha256"], a["doc_sha256"])
        finally:
            AB.FALLBACK_LEDGER, AB.KEYS_DIR, AB.MOTORE_DISPONIBILE = old
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=1)
