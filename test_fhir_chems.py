#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CH EMS document export — structural tests (the profile conformance itself is measured by chems_validate.py with
the official HL7 validator; these tests pin the exporter's own rules and its NULL controls)."""
import copy
import json
import os
import re
import unittest

import ambulanza_intelligente as A
import fhir_chems as C
from chems_validate import SAMPLE_MISSION, build_sample

ID_RE = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")


class TestChemsDocument(unittest.TestCase):
    def setUp(self):
        self.b = build_sample()
        self.res = [e["resource"] for e in self.b["entry"]]

    def test_document_shape(self):
        b = self.b
        self.assertEqual(b["type"], "document"); self.assertEqual(b["meta"]["profile"], [C.PROFILE["document"]])
        self.assertTrue(b["identifier"]["value"].startswith("urn:uuid:")); self.assertEqual(b["timestamp"], "2026-09-16T10:40:00+02:00")
        comp = b["entry"][0]["resource"]
        # 0.6.1: Composition.identifier (version-independent, ≠ Bundle.identifier) + confidentiality N with the CH Core EPR
        # extension WITHOUT display (tx.fhir.org rejects "Normal" for de-CH)
        self.assertTrue(comp["identifier"]["value"].startswith("urn:uuid:")); self.assertNotEqual(comp["identifier"]["value"], b["identifier"]["value"])
        self.assertEqual(comp["confidentiality"], "N")
        ext = comp["_confidentiality"]["extension"][0]
        self.assertEqual(ext["url"], "http://fhir.ch/ig/ch-core/StructureDefinition/ch-ext-epr-confidentialitycode")
        self.assertEqual(ext["valueCodeableConcept"]["coding"][0]["code"], "17621005"); self.assertNotIn("display", ext["valueCodeableConcept"]["coding"][0])
        comp = self.res[0]
        self.assertEqual(comp["resourceType"], "Composition"); self.assertEqual(comp["status"], "preliminary")
        self.assertEqual(comp["type"]["coding"][0]["code"], "67796-3"); self.assertEqual(comp["title"], "Einsatzprotokoll Rettungsdienst")
        codes = [s["code"]["coding"][0]["code"] for s in comp["section"]]
        self.assertEqual(codes[0], "1100001"); self.assertIn("1100006", codes); self.assertIn("1100011", codes); self.assertIn("48767-8", codes)
        for s in comp["section"]:
            self.assertIn("text", s); self.assertTrue(s["title"])
        self.assertIn('xml:lang="de"', comp["text"]["div"])
        fulls = {e["fullUrl"] for e in b["entry"]}
        self.assertEqual(len(fulls), len(b["entry"]))
        for r in self.res:
            self.assertTrue(ID_RE.match(r["id"]), r["id"]); self.assertIn("text", r)
        self.assertTrue(all(C.raggiungibili_dalla_composition(b).values()))                  # every entry reachable

    def test_encounter_servicerequest_and_organisations(self):
        enc = next(r for r in self.res if r["resourceType"] == "Encounter")
        mn = enc["identifier"][0]; self.assertEqual(mn["type"]["coding"][0]["code"], "MN"); self.assertEqual(mn["value"], "ZH-2026-000123")
        self.assertEqual(enc["identifier"][1]["type"]["coding"][0]["code"], "EVENT"); self.assertEqual(enc["identifier"][1]["value"], "42")
        self.assertEqual(enc["priority"]["coding"][0]["code"], "1000007"); self.assertEqual(enc["period"]["start"], "2026-09-16T10:12:00+02:00")
        sr = next(r for r in self.res if r["resourceType"] == "ServiceRequest")
        self.assertEqual(sr["requester"]["reference"], "#centrale"); self.assertEqual(sr["contained"][0]["identifier"][0]["value"], "7601002155939")
        self.assertEqual(enc["basedOn"][0]["reference"], next(e["fullUrl"] for e in self.b["entry"] if e["resource"] is sr))
        orgs = [r for r in self.res if r["resourceType"] == "Organization"]
        self.assertEqual({o["id"] for o in orgs}, {"soccorso", "destinazione"})
        for o in orgs:
            self.assertEqual(o["identifier"][0]["system"], C.OID_GLN)

    def test_observations_bound_to_patient_and_encounter(self):
        obs = [r for r in self.res if r["resourceType"] == "Observation"]
        enc_url = next(e["fullUrl"] for e in self.b["entry"] if e["resource"]["resourceType"] == "Encounter")
        pat_url = next(e["fullUrl"] for e in self.b["entry"] if e["resource"]["resourceType"] == "Patient")
        for o in obs:
            self.assertEqual(o["encounter"]["reference"], enc_url); self.assertEqual(o["subject"]["reference"], pat_url); self.assertIn("performer", o)
        hr = next(o for o in obs if o["id"] == "vit-hr"); self.assertEqual(hr["meta"]["profile"], [C.PROFILE["heartrate"]]); self.assertEqual(hr["valueQuantity"]["value"], 135.0)
        bp = next(o for o in obs if o["id"] == "vit-sbp"); self.assertEqual(bp["code"]["coding"][0]["code"], "85354-9"); self.assertEqual(bp["component"][0]["valueQuantity"]["value"], 85.0)
        times = sorted(o["code"]["coding"][0]["code"] for o in obs if o["id"].startswith("tempo-"))
        self.assertEqual(times, ["1000033", "1000035", "1000036", "1000037", "1000038"])
        for o in obs:
            if o["id"].startswith("tempo-"):
                self.assertEqual(o["valueDateTime"], o["effectiveDateTime"])
        pr = next(o for o in obs if o["id"] == "stato-paziente"); self.assertEqual(pr["valueCodeableConcept"]["coding"][0]["code"], "371240000")
        avpu = next(o for o in obs if o["id"] == "vit-avpu"); self.assertEqual(avpu["valueCodeableConcept"]["coding"][0]["code"], "A")

    def test_patient_anonymous_no_pii(self):
        pat = next(r for r in self.res if r["resourceType"] == "Patient")
        self.assertEqual(set(pat.keys()), {"resourceType", "id", "meta", "text"})                # the KEYS, not a substring

    def test_provenance_anchor_is_never_labelled_a_signature(self):
        """Council 16/09: a ledger digest is an ENTITY (anchor); Provenance.signature and Composition.attester appear
        only with a real record-bound Ed25519 signature, whose fields are validated strictly."""
        prov = next(r for r in self.res if r["resourceType"] == "Provenance")
        self.assertNotIn("signature", prov); self.assertNotIn("attester", self.res[0])
        self.assertEqual(prov["entity"][0]["what"]["identifier"]["value"], "ab" * 32)
        self.assertEqual(prov["target"][0]["reference"], self.b["entry"][0]["fullUrl"])
        import base64
        good = {"ancorato": True, "self_hash": "ab" * 32, "firma_b64": base64.b64encode(b"\x01" * 64).decode(),
                "pubkey_b64": base64.b64encode(b"\x02" * 32).decode(), "record_sha256": "cd" * 32}
        b = self._build(provenienza_omega=good)
        prov = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Provenance")
        self.assertNotIn("signature", prov)                                                                 # a FHIR Signature covers the targets: not ours
        ids = {e["what"]["identifier"]["system"].split("/")[-1]: e["what"]["identifier"]["value"] for e in prov["entity"]}
        self.assertEqual(ids["audit-record"], "cd" * 32); self.assertEqual(ids["audit-record-ed25519-signature"], good["firma_b64"]); self.assertEqual(ids["ed25519-pubkey"], good["pubkey_b64"])
        self.assertEqual(b["entry"][0]["resource"]["attester"][0]["mode"], "professional")
        with self.assertRaises(ValueError):                                                                # a signature without anchor is refused
            self._build(provenienza_omega={k: v for k, v in good.items() if k != "ancorato"})
        for bad in (dict(good, firma_b64="not base64!"), dict(good, firma_b64=base64.b64encode(b"\x01" * 63).decode()),
                    {k: v for k, v in good.items() if k != "pubkey_b64"}, dict(good, record_sha256="zz")):
            with self.assertRaises(ValueError):
                self._build(provenienza_omega=bad)

    def test_nothing_operational_is_invented(self):
        """period.start is the alarm time or the export fails; mission type only when given; event id shape-guarded."""
        m = {k: v for k, v in SAMPLE_MISSION.items()}; m["tempi"] = {"partenza": "2026-09-16T10:14:00+02:00"}
        with self.assertRaises(ValueError):
            self._build(missione={"tempi": m["tempi"]})
        enc = next(r for r in self.res if r["resourceType"] == "Encounter")
        self.assertNotIn("serviceType", enc); self.assertNotIn("end", enc["period"])
        b = self._build(missione={"tipo_missione": "secondaria", "tempi": dict(SAMPLE_MISSION["tempi"], consegna_paziente="2026-09-16T10:58:00+02:00")})
        e2 = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Encounter")
        self.assertEqual(e2["serviceType"]["coding"][0]["code"], "1000002"); self.assertEqual(e2["period"]["end"], "2026-09-16T10:58:00+02:00")
        for bad in ("Mario Rossi", "x" * 65, True, "a b"):
            with self.assertRaises(ValueError):
                self._build(missione={"incidente_id": bad})
        with self.assertRaises(ValueError):
            self._build(missione={"tipo_missione": "urgente"})

    def test_minimal_document_and_language(self):
        from chems_validate import build_minimal
        b = build_minimal(); comp = b["entry"][0]["resource"]
        codes = [s["code"]["coding"][0]["code"] for s in comp["section"]]
        self.assertEqual(codes, ["1100001", "1100006", "48767-8"])                                    # no handover: nothing known yet
        self.assertEqual(comp["language"], "fr"); self.assertIn("Intervention ZH-2026", comp["section"][0]["text"]["div"])
        self.assertFalse(any(e["resource"]["id"] == "vit-avpu" for e in b["entry"]))
        self.assertFalse(any(e["resource"]["resourceType"] == "Provenance" for e in b["entry"]))
        self.assertTrue(all(C.raggiungibili_dalla_composition(b).values()))
        self.assertNotEqual(b["identifier"]["value"], self.b["identifier"]["value"])
        # the full document: RR/SpO2/temperature are findings entries, not annotation entries
        full = self.res[0]["section"]; findings = next(s for s in full if s["code"]["coding"][0]["code"] == "1100006")
        ids = {e["reference"] for e in findings["entry"]}
        for k in ("rr", "spo2", "temp"):
            self.assertIn(next(e["fullUrl"] for e in self.b["entry"] if e["resource"]["id"] == f"vit-{k}"), ids)
        ann = next(s for s in full if s["code"]["coding"][0]["code"] == "48767-8")
        self.assertEqual(len(ann["entry"]), 1 + len([r for r in self.res if r["resourceType"] == "Flag"]) + 1)
        self.assertIn("Alter 67", next(r for r in self.res if r["resourceType"] == "Patient")["text"]["div"])
        # same mission + ts but another status → another document identifier
        b2 = self._build(stato="final"); self.assertNotEqual(b2["identifier"]["value"], self.b["identifier"]["value"])
        # 0.6.1: Composition.identifier is VERSION-INDEPENDENT — same mission number + alarm time → same value across
        # status and export instant; a different alarm time → a different value (null control)
        cid = lambda b: b["entry"][0]["resource"]["identifier"]["value"]
        b3 = self._build(ts="2026-09-16T11:55:00+02:00", stato="amended")
        self.assertEqual(cid(b2), cid(self.b)); self.assertEqual(cid(b3), cid(self.b))
        self.assertNotEqual(b3["identifier"]["value"], self.b["identifier"]["value"])
        t2 = copy.deepcopy(SAMPLE_MISSION["tempi"]); t2["allarme"] = "2026-09-16T09:00:00+02:00"
        self.assertNotEqual(cid(self._build(missione={"tempi": t2})), cid(self.b))
        # same instant spelled in UTC → same identifier (normalised); another patient of the same mission → another one
        import datetime as _dt
        t3 = copy.deepcopy(SAMPLE_MISSION["tempi"])
        t3["allarme"] = _dt.datetime.fromisoformat(SAMPLE_MISSION["tempi"]["allarme"]).astimezone(_dt.timezone.utc).isoformat()
        self.assertTrue(t3["allarme"].endswith("+00:00")); self.assertEqual(cid(self._build(missione={"tempi": t3})), cid(self.b))
        self.assertNotEqual(cid(self._build(missione={"prealert_id": "prealert-8"})), cid(self.b))
        # null controls: prealert_id is required ALWAYS (also without incidente_id), empty and bad tokens are refused,
        # a naive alarm time (no offset: host-timezone dependent) is refused before any identifier is derived
        m = copy.deepcopy(SAMPLE_MISSION); del m["prealert_id"]; del m["incidente_id"]
        with self.assertRaises(ValueError):
            self._build(missione_replace=m)
        for bad in ("", "bad token!", "x" * 65, True):
            with self.assertRaises(ValueError):
                self._build(missione={"prealert_id": bad})
        t4 = copy.deepcopy(SAMPLE_MISSION["tempi"]); t4["allarme"] = "2026-09-16T10:12:00"
        with self.assertRaises(ValueError):
            self._build(missione={"tempi": t4})
        # fractions of 1 or 5 digits pass _ISO and must not break the seed on Python 3.9/3.10 (fromisoformat grammar);
        # ".1" and ".100000" are the same instant → same identifier, and period.start keeps the string as given
        t5 = copy.deepcopy(SAMPLE_MISSION["tempi"]); t5["allarme"] = "2026-09-16T10:12:00.1+02:00"
        t6 = copy.deepcopy(SAMPLE_MISSION["tempi"]); t6["allarme"] = "2026-09-16T10:12:00.100000+02:00"
        b5, b6 = self._build(missione={"tempi": t5}), self._build(missione={"tempi": t6})
        self.assertEqual(cid(b5), cid(b6))
        self.assertEqual([e["resource"]["period"]["start"] for e in b5["entry"] if e["resource"]["resourceType"] == "Encounter"], ["2026-09-16T10:12:00.1+02:00"])

    # ── NULL controls: nothing required by CH EMS is ever invented ─────────────────────────────────────────────
    def _build(self, **over):
        vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135, alert_coscienza=True, temp=39.4)
        out = A.valuta_paziente(vit, [], 67, 8)
        m = over.pop("missione_replace", None)          # a whole mission dict, not merged over SAMPLE_MISSION
        if m is None:
            m = copy.deepcopy(SAMPLE_MISSION); m.update(over.pop("missione", {}))
        return C.prealert_to_chems_document(out["PRE_ALERT_INTEGRATO"], vit, over.pop("ts", "2026-09-16T10:40:00+02:00"), m, **over)

    def test_null_controls_refuse(self):
        bad = [dict(missione={"numero_missione": ""}), dict(missione={"sistema_oid": "2.16.756"}), dict(missione={"organizzazione": {"nome": "x", "gln": "7601002155930"}}),
               dict(missione={"organizzazione": {"nome": "x"}}), dict(missione={"richiedente": {"nome": "", "gln": "7601002155939"}}),
               dict(missione={"tempi": {"arrivo": "2026-09-16T10:12:00+02:00"}}), dict(missione={"tempi": {"allarme": "2026-09-16 10:12"}}),
               dict(missione={"triage_colore": "nero"}), dict(missione={"urgenza": "lampeggianti"}), dict(missione={"lingua": "rm"}),
               dict(ts="2026-09-16T10:40:00"), dict(stato="draft"), dict(provenienza_omega={"ancorato": True, "self_hash": "zz"})]
        for over in bad:
            with self.assertRaises(ValueError, msg=str(over)):
                self._build(**over)
        self.assertFalse(C.gln_valida("7601002155930")); self.assertFalse(C.gln_valida("760100215593")); self.assertTrue(C.gln_valida("7601002155939"))

    def test_unknown_consciousness_is_not_exported_as_a_code(self):
        vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135, alert_coscienza=False, temp=39.4)
        out = A.valuta_paziente(vit, [], 67, 8)
        b = C.prealert_to_chems_document(out["PRE_ALERT_INTEGRATO"], vit, "2026-09-16T10:40:00+02:00", SAMPLE_MISSION)
        self.assertFalse(any(e["resource"]["id"] == "vit-avpu" for e in b["entry"]))         # V/P/U are unknown → no AVPU code
        self.assertTrue(all(C.raggiungibili_dalla_composition(b).values()))

    def test_reachability_check_can_fail(self):
        b = copy.deepcopy(self.b)
        b["entry"].append({"fullUrl": "urn:uuid:00000000-0000-0000-0000-000000000001", "resource": {"resourceType": "Observation", "id": "orfano", "status": "final", "code": {"text": "x"}}})
        r = C.raggiungibili_dalla_composition(b)
        self.assertFalse(r["urn:uuid:00000000-0000-0000-0000-000000000001"]); self.assertEqual(sum(1 for v in r.values() if not v), 1)


class TestFirmaDocumento(unittest.TestCase):
    """0.7.3 — Bundle.signature (detached JWS EdDSA over JCS of the Bundle without `signature`) and Composition.attester.
    Every negative here is a POSITIVE CONTROL of the verifier. Trust and mathematics are two verdicts: OK_REGISTRATA only
    when the embedded key equals the operator's registered key; a fresh key under the same kid is OK_CHIAVE_NON_REGISTRATA."""
    def setUp(self):
        import audit_bridge as AB, tempfile, shutil
        self.AB = AB; self._orig = (AB.KEYS_DIR, AB.FALLBACK_LEDGER, AB.MOTORE_DISPONIBILE)
        self._prod_keys = set(os.listdir(AB.KEYS_DIR)) if os.path.isdir(AB.KEYS_DIR) else None      # isolation: measured, not assumed
        self.d = tempfile.mkdtemp(prefix="chems-sig-"); AB.KEYS_DIR = self.d + "/keys"; AB.FALLBACK_LEDGER = self.d + "/fb.jsonl"; AB.MOTORE_DISPONIBILE = False
        self.addCleanup(lambda: (setattr(AB, "KEYS_DIR", self._orig[0]), setattr(AB, "FALLBACK_LEDGER", self._orig[1]), setattr(AB, "MOTORE_DISPONIBILE", self._orig[2]), shutil.rmtree(self.d, ignore_errors=True)))
        if not AB.FIRMA_LOCALE_DISPONIBILE:
            self.skipTest("cryptography missing: no local Ed25519 signer")
        self.doc = build_sample()
        self.signed = C.firma_documento(self.doc, "equipaggio-118-alfa", "2026-09-19T09:11:00+02:00")

    def tearDown(self):
        prod = set(os.listdir(self._orig[0])) if os.path.isdir(self._orig[0]) else None
        self.assertEqual(prod, self._prod_keys, "the test wrote into the production key store")
        self.assertTrue(os.path.exists(self.d + "/keys/fb-equipaggio-118-alfa.pub"), "the sandbox registry was not used")

    def _jws(self, doc=None):
        import base64
        return base64.b64decode((doc or self.signed)["signature"]["data"]).decode()

    def _rewrap(self, doc, jws):
        import base64
        t = copy.deepcopy(doc); t["signature"]["data"] = base64.b64encode(jws.encode()).decode(); return t

    def test_sign_verify_and_caller_untouched(self):
        self.assertNotIn("signature", self.doc); self.assertNotIn("attester", self.doc["entry"][0]["resource"])   # deep copy
        v = C.verifica_firma_documento(self.signed)
        self.assertEqual((v["stato"], v["kid"], v["chiave_registrata"]), ("OK_REGISTRATA", "omega:fb-equipaggio-118-alfa", True))
        raw = json.dumps(self.signed, ensure_ascii=False, indent=2).encode("utf-8")          # any serialisation of the same JSON
        self.assertEqual(C.verifica_firma_documento(raw)["stato"], "OK_REGISTRATA")
        sig = self.signed["signature"]
        self.assertEqual(sig["type"][0]["code"], "1.2.840.10065.1.12.1.1"); self.assertEqual(sig["sigFormat"], "application/jose")
        self.assertEqual(sig["targetFormat"], C.TARGET_FORMAT); self.assertIn("rfc8785-bundle-without-signature", C.TARGET_FORMAT)
        att = self.signed["entry"][0]["resource"]["attester"]
        self.assertEqual([a["mode"] for a in att], ["professional"]); self.assertEqual(att[0]["party"], sig["who"])
        jws = self._jws(); h = json.loads(C._b64u_dec(jws.split(".")[0]))
        self.assertEqual((h["alg"], h["b64"], h["crit"], h["sigT"], h["canon"], h["who"]), ("EdDSA", False, ["b64"], sig["when"], C.CANON_URI, sig["who"]["reference"]))
        self.assertEqual(h["srCms"][0]["commId"]["id"], "urn:oid:1.2.840.10065.1.12.1.1")
        self.assertEqual(set(h["jwk"]), {"kty", "crv", "x"}); self.assertEqual(h["jwk"]["crv"], "Ed25519")   # PUBLIC part only, never "d"
        self.assertEqual(jws.split(".")[1], "")                                                # detached payload
        self.assertEqual(C.verifica_firma_documento(self.doc)["stato"], "ASSENTE")
        v2 = C.verifica_firma_documento(self.signed, keys_dir=self.d + "/nessuno")            # no registry at all
        self.assertEqual((v2["stato"], v2["chiave_registrata"]), ("OK_CHIAVE_NON_REGISTRATA", False))

    def test_key_substitution_is_not_registered(self):
        """The attack an embedded-JWK design must survive: a fresh key, same kid, valid mathematics → never OK_REGISTRATA."""
        import shutil, tempfile
        altro = tempfile.mkdtemp(prefix="chems-rogue-"); self.addCleanup(shutil.rmtree, altro, True)
        self.AB.KEYS_DIR = altro + "/keys"                       # a different machine generates its own key for the same name
        t = copy.deepcopy(self.doc); t["entry"][1]["resource"]["text"]["div"] = t["entry"][1]["resource"]["text"]["div"].upper()
        rogue = C.firma_documento(t, "equipaggio-118-alfa", "2026-09-19T09:11:00+02:00")
        self.AB.KEYS_DIR = self.d + "/keys"
        v = C.verifica_firma_documento(rogue)                    # verified against the VICTIM's registry
        self.assertEqual((v["stato"], v["kid"], v["chiave_registrata"]), ("OK_CHIAVE_NON_REGISTRATA", "omega:fb-equipaggio-118-alfa", False))
        self.assertEqual(C.verifica_firma_documento(rogue, keys_dir=altro + "/keys")["stato"], "OK_REGISTRATA")   # …and on the rogue machine it is "its" key
        import chems_ingest as I
        self.assertEqual(I.leggi_documento(json.dumps(rogue).encode())["firma"]["stato"], "OK_CHIAVE_NON_REGISTRATA")

    def test_every_tampering_is_non_valida(self):
        import base64
        casi = {}
        t = copy.deepcopy(self.signed); t["entry"][1]["resource"]["text"]["div"] = t["entry"][1]["resource"]["text"]["div"].upper(); casi["valore"] = t
        t = copy.deepcopy(self.signed); t["entry"].append({"fullUrl": "urn:uuid:x", "resource": {"resourceType": "Basic", "id": "x"}}); casi["entry aggiunta"] = t
        t = copy.deepcopy(self.signed); del t["entry"][-1]; casi["entry tolta"] = t
        t = copy.deepcopy(self.signed); t["entry"][0]["resource"]["attester"][0]["mode"] = "legal"; casi["attester mode"] = t
        t = copy.deepcopy(self.signed); t["signature"]["when"] = "2026-09-19T09:12:00+02:00"; casi["when≠sigT"] = t
        t = copy.deepcopy(self.signed); t["signature"]["sigFormat"] = "application/pkcs7-mime"; casi["sigFormat"] = t
        t = copy.deepcopy(self.signed); t["signature"]["targetFormat"] = "application/fhir+json"; casi["targetFormat non firmato"] = t
        t = copy.deepcopy(self.signed); t["signature"]["type"][0]["code"] = "1.2.840.10065.1.12.1.5"; casi["type ≠ srCms"] = t
        centrale = next(e["fullUrl"] for e in self.signed["entry"] if e["resource"].get("id") == "destinazione")
        t = copy.deepcopy(self.signed); t["signature"]["who"] = {"reference": centrale}; casi["who → other Organization"] = t
        t = json.loads(json.dumps(self.signed).replace('"status"', '"status2"', 1)); casi["chiave rinominata"] = t
        t = copy.deepcopy(self.signed); t["meta"]["profile"] = ["http://example.org/other"]; casi["meta.profile (signed: plain variant, not #document)"] = t
        jws = self._jws(); h, _, sg = jws.split(".")
        raw = bytearray(C._b64u_dec(sg)); raw[10] ^= 0x01                                    # well-formed 64-byte signature, one bit wrong
        casi["un bit della firma"] = self._rewrap(self.signed, f"{h}..{C._b64u(bytes(raw))}")
        casi["firma troncata"] = self._rewrap(self.signed, f"{h}..{sg[:-8]}")
        def _hdr(**mod):
            hd = json.loads(C._b64u_dec(h)); hd.update(mod); hd = {k: v for k, v in hd.items() if v is not None}
            return self._rewrap(self.signed, C._b64u(json.dumps(hd, separators=(",", ":"), sort_keys=True).encode()) + ".." + sg)
        casi["alg none"] = _hdr(alg="none"); casi["alg HS256"] = _hdr(alg="HS256"); casi["crv Ed448"] = _hdr(jwk={"kty": "OKP", "crv": "Ed448", "x": "AA"})
        casi["b64 true"] = _hdr(b64=True); casi["crit extra"] = _hdr(crit=["b64", "exp"]); casi["crit assente"] = _hdr(crit=None)
        casi["sigT assente"] = _hdr(sigT=None); casi["canon diversa"] = _hdr(canon="http://hl7.org/fhir/canonicalization/json")
        casi["who nel header diverso"] = _hdr(who="urn:uuid:altro"); casi["kid traversal"] = _hdr(kid="omega:fb-../../etc/passwd")
        casi["jwk con chiave privata"] = _hdr(jwk={"kty": "OKP", "crv": "Ed25519", "x": json.loads(C._b64u_dec(h))["jwk"]["x"], "d": "AA"})
        for nome, x in casi.items():
            self.assertEqual(C.verifica_firma_documento(x)["stato"], "NON_VALIDA", nome)
        # duplicate keys INSIDE a signed document (last-wins would equal the signed value): refused on the bytes
        raw = json.dumps(self.signed).replace('"status": "preliminary"', '"status": "final", "status": "preliminary"', 1)
        self.assertIn('"status": "final", "status": "preliminary"', raw)
        self.assertEqual(C.verifica_firma_documento(raw.encode())["stato"], "NON_VALIDA")
        self.assertEqual(C.verifica_firma_documento({"resourceType": "Patient"})["stato"], "NON_VALIDA")
        self.assertEqual(C.verifica_firma_documento(b'{"resourceType":"Bundle","signature":{"sigFormat":"application/jose","data":"x","targetFormat":"' + C.TARGET_FORMAT.encode() + b'","x":"\\ud800"}}')["stato"], "NON_VALIDA")   # lone surrogate: a verdict, not a crash
        with self.assertRaises(ValueError):
            C.firma_documento(self.signed, "equipaggio-118-alfa", "2026-09-19T09:11:00+02:00")   # one signature per document
        k = json.loads(C._b64u_dec(self._jws(C.firma_documento(self.doc, "../x", "2026-09-19T09:11:00+02:00")).split(".")[0]))["kid"]
        self.assertRegex(k, r"^omega:fb-[a-z0-9-]{1,64}$"); self.assertNotIn("..", k)          # slug sanitised at the signer too

    def test_structure_is_judged_before_cryptography(self):
        """Without Ed25519 a valid document is NON_VERIFICATA, but a malformed one is still NON_VALIDA."""
        from unittest import mock
        with mock.patch.object(C, "_ed25519_verify", return_value=None):
            v = C.verifica_firma_documento(self.signed); self.assertEqual((v["stato"], v["chiave_registrata"]), ("NON_VERIFICATA", True))
            t = copy.deepcopy(self.signed); t["signature"]["when"] = "2026-09-19T09:12:00+02:00"
            self.assertEqual(C.verifica_firma_documento(t)["stato"], "NON_VALIDA")
            t = copy.deepcopy(self.signed); t["signature"]["sigFormat"] = "x"
            self.assertEqual(C.verifica_firma_documento(t)["stato"], "NON_VALIDA")
            self.assertEqual(C.verifica_firma_documento({"resourceType": "Patient"})["stato"], "NON_VALIDA")

    def test_jcs_signs_numbers_not_spellings(self):
        """RFC 8785 §3.2.2.3: 39.4 and 39.40 canonicalise to the same bytes — measured on the bytes, not through json.loads."""
        raw = json.dumps(self.signed); self.assertRegex(raw, r'"value": 39\.4[,}]')
        self.assertEqual(C.verifica_firma_documento(raw.replace('"value": 39.4', '"value": 39.40', 1).encode())["stato"], "OK_REGISTRATA")
        self.assertEqual(C._es6_number(39.40), "39.4")

    def test_independent_jws_library_agrees(self):
        """Oracle: jwcrypto (EdDSA, detached payload) verifies the same bytes against the REGISTERED public key file — not
        the header's — and refuses a tampered payload and a base64url-encoded (b64:true) payload."""
        try:
            from jwcrypto import jws as J, jwk as K
        except ImportError:
            self.skipTest("jwcrypto not installed")
        import base64
        pub = base64.b64decode(open(self.d + "/keys/fb-equipaggio-118-alfa.pub").read().strip())
        key = K.JWK(kty="OKP", crv="Ed25519", x=C._b64u(pub))
        raw = self._jws(); payload = C.jcs({k: v for k, v in self.signed.items() if k != "signature"})
        j = J.JWS(); j.deserialize(raw); j.verify(key, detached_payload=payload)
        for bad in (payload + b" ", C._b64u(payload).encode()):
            with self.assertRaises(Exception):
                j2 = J.JWS(); j2.deserialize(raw); j2.verify(key, detached_payload=bad)

    def test_reader_reports_attester_and_signature(self):
        import chems_ingest as I
        r = I.leggi_documento(json.dumps(self.signed).encode())
        self.assertEqual(r["firma"]["stato"], "OK_REGISTRATA"); self.assertEqual(r["attestazioni"][0]["mode"], "professional")
        r2 = I.leggi_documento(json.dumps(self.doc).encode()); self.assertEqual(r2["firma"]["stato"], "ASSENTE"); self.assertEqual(r2["attestazioni"], [])
        with open("examples/chems_conformance/ig-Bundle-2-Einsatzprotokoll.json", "rb") as fh:     # the IG example: attester legal, no signature
            r3 = I.leggi_documento(fh.read())
        self.assertEqual(r3["attestazioni"][0]["mode"], "legal"); self.assertEqual(r3["firma"]["stato"], "ASSENTE")

    def test_published_signed_sample_is_deterministic_and_verifies(self):
        from chems_validate import build_signed_sample
        a, b = build_signed_sample(), build_signed_sample()
        self.assertEqual(a, b)
        v = C.verifica_firma_documento(a); self.assertEqual((v["stato"], v["chiave_registrata"]), ("OK_CHIAVE_NON_REGISTRATA", False))   # public key: format, not identity
        with open("examples/chems_document_sample_signed.json") as fh:
            self.assertEqual(json.load(fh), a)                                                  # the committed file IS the build
        self.assertFalse(os.path.exists(self.d + "/keys/fb-esempio.pub"), "the sample key must not enter the registry")


class TestVerificaSenzaFirmatario(unittest.TestCase):
    """Runs with or without `cryptography`: RFC 8785 vectors, rejections, and the verdict on the PUBLISHED signed sample."""
    def test_jcs_vectors(self):
        # RFC 8785 Appendix B (all rows) + the ES6 threshold neighbours
        for f, want in ((5e-324, "5e-324"), (1.7976931348623157e+308, "1.7976931348623157e+308"), (0.0, "0"), (-0.0, "0"), (1e21, "1e+21"),
                        (1e-7, "1e-7"), (0.000001, "0.000001"), (9.999999999999997e-7, "9.999999999999997e-7"), (1e23, "1e+23"),
                        (9.999999999999997e+22, "9.999999999999997e+22"), (1.0000000000000001e+23, "1.0000000000000001e+23"), (295147905179352830000.0, "295147905179352830000"),
                        (999999999999999900000.0, "999999999999999900000"), (333333333.33333325, "333333333.33333325"),
                        (-0.0000033333333333333333, "-0.0000033333333333333333"), (0.05, "0.05"), (100.0, "100"), (39.4, "39.4")):
            self.assertEqual(C._es6_number(f), want, repr(f))
        self.assertEqual(C.jcs({"b": 1, "a": [True, None, 1.5, "x"], "\u20ac": 0}), '{"a":[true,null,1.5,"x"],"b":1,"\u20ac":0}'.encode("utf-8"))
        self.assertEqual(C.jcs({"\ufb33": 1, "\U0001f600": 2}), '{"\U0001f600":2,"\ufb33":1}'.encode("utf-8"))   # UTF-16 code units: the surrogate pair sorts first
        self.assertEqual(C.jcs({"s": "\u001f\u007f\u2028\"\\"}), b'{"s":"\\u001f\x7f\xe2\x80\xa8\\"\\\\"}')
        for bad in (float("nan"), float("inf"), 2 ** 53 + 1):
            with self.assertRaises((ValueError, TypeError)):
                C.jcs({"x": bad})
        self.assertEqual(C.jcs({"x": 9007199254740992}), b'{"x":9007199254740992}')     # 2^53 itself is exact

    def test_published_signed_sample_verdict(self):
        import audit_bridge as AB
        with open("examples/chems_document_sample_signed.json", "rb") as fh:
            v = C.verifica_firma_documento(fh.read())
        self.assertEqual(v["stato"], "OK_CHIAVE_NON_REGISTRATA" if AB.FIRMA_LOCALE_DISPONIBILE else "NON_VERIFICATA", v)
        self.assertEqual((v["kid"], v["chiave_registrata"]), ("omega:fb-esempio", False))


class TestPazienteIdentificato(unittest.TestCase):
    """0.7.3 — handover stage, opt-in identity for an EPR-conformant document (measured 2026-09-19: the three
    ch-ems-epr-* warnings disappear; evidence in examples/chems_conformance/release_0.7.3/)."""
    PAZ = {"cognome": "Muster", "nome": "Petra", "sesso": "female", "data_nascita": "1959-03-04",
           "identificatore": {"system": "urn:oid:2.16.756.5.30.1.999.2", "value": "MPI-000123"}}

    def _doc(self, paz):
        p = A.valuta_paziente({"rr": 18, "spo2": 97, "su_ossigeno": False, "sbp": 120, "hr": 80, "alert_coscienza": True, "temp": 36.8}, [], 67, 8)["PRE_ALERT_INTEGRATO"]
        return C.prealert_to_chems_document(p, p["vitali"], "2026-09-19T09:10:00+02:00", dict(SAMPLE_MISSION, paziente=paz))

    def test_identified_patient_has_what_epr_requires(self):
        pat = self._doc(self.PAZ)["entry"][1]["resource"]
        self.assertEqual(pat["identifier"], [{"system": "urn:oid:2.16.756.5.30.1.999.2", "value": "MPI-000123"}])
        self.assertEqual(pat["name"], [{"family": "Muster", "given": ["Petra"]}]); self.assertEqual((pat["gender"], pat["birthDate"]), ("female", "1959-03-04"))
        self.assertEqual(set(pat), {"resourceType", "id", "meta", "text", "identifier", "name", "gender", "birthDate"})
        self.assertIn("Muster", pat["text"]["div"]); self.assertNotIn("<b>", pat["text"]["div"])
        anon = self._doc(None)["entry"][1]["resource"]; self.assertEqual(set(anon), {"resourceType", "id", "meta", "text"})   # default unchanged

    def test_identity_only_in_the_document(self):
        """paziente + firma + lettura together (the real handover path); the identity is in the document and nowhere else."""
        import audit_bridge as AB, tempfile, shutil, chems_ingest as I
        if not AB.FIRMA_LOCALE_DISPONIBILE:
            self.skipTest("cryptography missing")
        d = tempfile.mkdtemp(prefix="chems-id-"); orig = (AB.KEYS_DIR, AB.FALLBACK_LEDGER, AB.MOTORE_DISPONIBILE)
        AB.KEYS_DIR, AB.FALLBACK_LEDGER, AB.MOTORE_DISPONIBILE = d + "/keys", d + "/fb.jsonl", False
        self.addCleanup(lambda: (setattr(AB, "KEYS_DIR", orig[0]), setattr(AB, "FALLBACK_LEDGER", orig[1]), setattr(AB, "MOTORE_DISPONIBILE", orig[2]), shutil.rmtree(d, True)))
        doc = C.firma_documento(self._doc(dict(self.PAZ, cognome="D'Angelo & Figli")), "eq-1", "2026-09-19T09:11:00+02:00", attester="legal")
        pat = doc["entry"][1]["resource"]; self.assertEqual(pat["id"], "paziente")
        self.assertIn("D'Angelo &amp; Figli", pat["text"]["div"]); self.assertNotIn("& ", pat["text"]["div"])       # escaped, never raw
        self.assertEqual(doc["entry"][0]["resource"]["subject"]["reference"], doc["entry"][1]["fullUrl"])              # subject → the identified patient
        r = I.leggi_documento(json.dumps(doc, ensure_ascii=False).encode()); self.assertEqual(r["firma"]["stato"], "OK_REGISTRATA")
        self.assertEqual(r["attestazioni"][0]["mode"], "legal")
        rec = I.ancora_documento(json.dumps(doc, ensure_ascii=False).encode(), "eq-1")                                # anchoring keeps digests only
        ledger = open(AB.FALLBACK_LEDGER, encoding="utf-8").read()
        for pii in ("Angelo", "Petra", "MPI-000123", "1959-03-04"):
            self.assertNotIn(pii, ledger, pii); self.assertNotIn(pii, json.dumps(rec), pii)

    def test_refusals(self):
        for bad, why in (({**self.PAZ, "identificatore": {"system": C.OID_EPR_SPID, "value": "761337610411265304"}}, "EPR-SPID"),
                         ({**self.PAZ, "identificatore": {"system": C.OID_AHVN13, "value": "7561234567897"}}, "AHVN13"),
                         ({**self.PAZ, "data_nascita": "1959-02-30"}, "calendar"), ({**self.PAZ, "data_nascita": "04.03.1959"}, "YYYY-MM-DD"),
                         ({**self.PAZ, "cognome": "<script>"}, "printable"), ({k: v for k, v in self.PAZ.items() if k != "cognome"}, "family"),
                         ({**self.PAZ, "sesso": "F"}, "administrative-gender"), ({**self.PAZ, "identificatore": {"system": "http://x", "value": "1"}}, "urn:oid"),
                         ({**self.PAZ, "identificatore": {"system": "urn:oid:2.16.756.5.30.1.999.2", "value": "7561234567897"}}, "AHVN13"),
                         ("Muster", "object")):
            with self.assertRaises(ValueError, msg=why) as cm:
                self._doc(bad)
            self.assertIn(why, str(cm.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
