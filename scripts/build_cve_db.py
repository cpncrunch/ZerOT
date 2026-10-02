#!/usr/bin/env python3
"""Build the curated OT CVE database from the NVD 2.0 API (live queries).

Every entry shipped in data/ot_cves.json was fetched from NVD at build time —
nothing is hand-typed from memory. Offline lookup only at runtime; this script
is the sole writer and is run manually when refreshing the db.

NVD asks for <=1 req / 6s without an API key: queries are serialized + slept.
"""
import json
import time
import urllib.request
import urllib.parse
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "ot_cves.json"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# product families the tool can already identify:
#   keys -> where ZerOT extracts the product string today
PRODUCTS = {
    "Allen-Bradley ControlLogix 1756": ["ControlLogix 1756", "1756-L", "1756-ENBT"],
    "Allen-Bradley Micro800": ["Micro830", "Micro850", "Micro870"],
    "Siemens S7-300": ["CPU 315", "S7-300", "6ES7 315", "6GK7"],
    "Siemens S7-1200": ["S7-1200", "CPU 121", "6ES7 21"],
    "Siemens S7-1500": ["S7-1500", "CPU 15", "6ES7 51"],
    "Siemens SCALANCE switch": ["SCALANCE X", "SCALANCE XM"],
    "Schneider Modicon M340": ["Modicon M340", "BMX AMI"],
    "Schneider Modicon M221": ["Modicon M221", "TM221"],
    "Schneider Modicon Quantum": ["Modicon Quantum", "140-CPU"],
    "Schneider BMX NOE": ["BMX NOE", "BMXNOE"],
    "GE DNP3 / Mark VIe": ["Mark VIe", "DS200"],
    "Moxa NPort": ["NPort 5", "NPort 6", "NPort AI"],
    "Moxa EDS switch": ["EDS-4", "EDS-5", "EDS-8", "EDS-2"],
    "Wago 750/ PFC": ["WAGO 750-", "PFC200"],
    "MELSEC iQ-R": ["iQ-R", "R08CPU", "R16CPU"],
    "Omron CJ2 / NX": ["CJ2M", "NX1P", "NX102"],
    "Honeywell TDC": ["TDC 3000", "Experion PKS"],
    "Yokogawa CENTUM": ["CENTUM VP", "CENTUM CS"],
    "BACnet controller (generic)": ["BACnet"],
}


def nvd_query(kw, retries=4):
    for attempt in range(retries):
        try:
            url = f"{API}?keywordSearch={urllib.parse.quote(kw)}&resultsPerPage=60"
            req = urllib.request.Request(url, headers={"User-Agent": "zerot-cve-builder"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as ex:
            wait = 8 * (attempt + 1)
            print(f"  ! {kw}: {ex} — retry in {wait}s")
            time.sleep(wait)
    return None


# a CVE is kept only if its description names the vendor or a family token —
# NVD keywordSearch matches full text, so generic tokens pull unrelated hits
VENDOR_TOKENS = {
    "Allen-Bradley ControlLogix 1756": ["rockwell", "allen-bradley", "controllogix", "1756"],
    "Allen-Bradley Micro800": ["rockwell", "allen-bradley", "micro8"],
    "Siemens S7-300": ["siemens", "simatic", "s7-300", "6es7 315", "6gk7"],
    "Siemens S7-1200": ["siemens", "simatic", "s7-1200", "6es7 21"],
    "Siemens S7-1500": ["siemens", "simatic", "s7-1500", "6es7 51"],
    "Siemens SCALANCE switch": ["siemens", "scalance"],
    "Schneider Modicon M340": ["schneider", "modicon", "m340", "bmx"],
    "Schneider Modicon M221": ["schneider", "modicon", "tm221", "m221"],
    "Schneider Modicon Quantum": ["schneider", "modicon", "quantum", "140-cpu"],
    "Schneider BMX NOE": ["schneider", "bmx noe", "bmxnoe"],
    "GE DNP3 / Mark VIe": ["ge mark", "mark vie", "mark vi", "generalelectric", "ds200"],
    "Moxa NPort": ["moxa", "nport"],
    "Moxa EDS switch": ["moxa", "eds-"],
    "Wago 750/ PFC": ["wago", "pfc200"],
    "MELSEC iQ-R": ["mitsubishi", "melsec", "iq-r", "r08cpu", "r16cpu"],
    "Omron CJ2 / NX": ["omron", "cj2", "nx1p", "nx102"],
    "Honeywell TDC": ["honeywell", "tdc 3000", "experion"],
    "Yokogawa CENTUM": ["yokogawa", "centum"],
    "BACnet controller (generic)": ["bacnet"],
}


def relevant(family, desc):
    d = desc.lower()
    return any(t in d for t in VENDOR_TOKENS.get(family, [family.lower()]))


def main():
    db = {"_meta": {"source": "NVD 2.0 API", "generated": time.strftime("%Y-%m-%d"),
                    "note": "curated offline lookup; verify at report time"},
          "products": {}}
    total = 0
    for family, queries in PRODUCTS.items():
        entries = {}
        for kw in queries:
            print(f"query: {kw!r} ...", flush=True)
            d = nvd_query(kw)
            time.sleep(6.5)
            if not d:
                continue
            for v in d.get("vulnerabilities", []):
                c = v["cve"]
                cid = c["id"]
                desc = next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), "")
                metrics = c.get("metrics", {})
                cvss = None
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(k):
                        m = metrics[k][0].get("cvssData", {})
                        cvss = m.get("baseScore")
                        if cvss is not None:
                            break
                # year filter: skip ancient advisories? keep >= 2010 for signal
                year = int(cid.split("-")[1])
                if year < 2010 or "security-research" in cid:
                    continue
                if not relevant(family, desc):
                    continue
                if cid not in entries:
                    entries[cid] = {
                        "id": cid, "cvss": cvss,
                        "desc": desc[:180],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                    }
            if d.get("totalResults", 0) > 60:
                print(f"  (note: {kw} has {d['totalResults']} results; kept first page)")
        if entries:
            db["products"][family] = sorted(entries.values(), key=lambda x: -(x["cvss"] or 0))
            total += len(entries)
            print(f"  -> {family}: {len(entries)} CVEs")
    db["_meta"]["total_cves"] = total
    OUT.write_text(json.dumps(db, indent=1))
    print(f"\nwrote {OUT} ({total} CVEs across {len(db['products'])} families)")


if __name__ == "__main__":
    main()
