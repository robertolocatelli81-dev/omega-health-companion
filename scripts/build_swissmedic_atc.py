#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Costruisce swissmedic_gtin_atc.py (modulo dati) dalla lista UFFICIALE Swissmedic «Zugelassene Packungen» (Humanarzneimittel):
GTIN → ATC. Il GTIN svizzero è derivato come GS1 fa per la Svizzera: 7680 + n° autorizzazione (5 cifre)
+ codice confezione (3 cifre) + cifra di controllo GS1 — formula verificata sui GTIN degli esempi pubblicati dell'IG CH EMS
(7680405580012 Nitrolingual, 7680539870027 Fentanyl Sintetica). Provenienza registrata nel file (URL, sha256, «Stand»).
Solo libreria standard (xlsx = zip + xml). Uso: python3 scripts/build_swissmedic_atc.py [file.xlsx già scaricato]"""
import hashlib, json, os, re, sys, urllib.request, zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

URL = ("https://www.swissmedic.ch/dam/swissmedic/de/dokumente/internetlisten/"
       "zugelassene_packungen_human.xlsx.download.xlsx/zugelassene_packungen_ham.xlsx")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "swissmedic_gtin_atc.py")   # modulo: entra nella wheel
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def gs1_check(d12: str) -> int:
    s = sum(int(c) * (3 if i % 2 == 0 else 1) for i, c in enumerate(reversed(d12)))
    return (10 - s % 10) % 10


def gtin_ch(zulassung: str, packung: str) -> str:
    body = "7680" + zulassung.zfill(5) + packung.zfill(3)
    return body + str(gs1_check(body))


def rows_of(xlsx: bytes):
    z = zipfile.ZipFile(__import__("io").BytesIO(xlsx))
    ss = ["".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])) for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS)]
    for r in ET.fromstring(z.read("xl/worksheets/sheet1.xml")).iter("{%s}row" % NS["m"]):
        vals = {}
        for c in r.findall("m:c", NS):
            col = re.match(r"[A-Z]+", c.get("r")).group(0); v = c.find("m:v", NS)
            if v is not None:
                vals[col] = ss[int(v.text)] if c.get("t") == "s" else v.text
        yield vals


def main() -> int:
    if len(sys.argv) > 1:
        raw = open(sys.argv[1], "rb").read(); src = sys.argv[1]
    else:
        raw = urllib.request.urlopen(URL, timeout=300).read(); src = URL
    rows = list(rows_of(raw))
    hdr_i = next(i for i, r in enumerate(rows) if any("GTIN" in str(v) or "ATC" in str(v) for v in r.values()))
    hdr = rows[hdr_i]
    col = {}
    for k, v in hdr.items():
        t = " ".join(str(v).split())                     # le intestazioni hanno a capo interni
        if t.startswith("Zulassungs-nummer"): col["zn"] = k        # non "Zulassungsinhaberin" (titolare)
        elif t.startswith("Bezeichnung"): col["nome"] = k
        elif t.startswith("ATC"): col["atc"] = k
        elif t.startswith("Packungscode"): col["pc"] = k
        elif t.startswith("Wirkstoff"): col["ws"] = k
    stand = next((str(v) for r in rows[:hdr_i] for v in r.values() if "Stand" in str(v)), "")
    out = {}
    for r in rows[hdr_i + 1:]:
        zn, pc, atc = r.get(col["zn"]), r.get(col["pc"]), r.get(col["atc"])
        if not (zn and pc and atc) or not str(zn).isdigit() or not str(pc).isdigit():
            continue
        g = gtin_ch(str(zn), str(pc))
        out[g] = str(atc).strip()                      # solo l'ATC: il nome resta quello scritto nel documento
    doc = {"_provenienza": {"fonte": "Swissmedic, Zugelassene Packungen (Humanarzneimittel)", "url": URL,
                            "origine": "download diretto" if src == URL else "file locale (stesso contenuto: vedi sha256)",
                            "sha256_xlsx": hashlib.sha256(raw).hexdigest(), "stand": stand,
                            "costruito": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "gtin_derivazione": "7680 + Zulassungsnummer(5) + Packungscode(3) + cifra GS1; verificata su 7680405580012 e 7680539870027 (esempi IG CH EMS)",
                            "n": len(out)},
           "gtin": out}
    with open(OUT, "w", encoding="utf-8") as f:
        f.write('# -*- coding: utf-8 -*-\n"""GENERATO da scripts/build_swissmedic_atc.py — NON modificare a mano. GTIN svizzero -> codice ATC,\n'
                'dalla lista ufficiale Swissmedic "Zugelassene Packungen" (provenienza sotto)."""\n')
        f.write("PROVENIENZA = " + json.dumps(doc["_provenienza"], ensure_ascii=False, indent=1) + "\n")
        f.write("GTIN_ATC = " + json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(json.dumps({"n": len(out), "stand": stand, "out": OUT, "size": os.path.getsize(OUT)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
