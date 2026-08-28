#!/usr/bin/env python3
"""Anker: dieselben Token-Faelle durch die REFERENZ (jarvis-email-dashboard).

    ~/Developer/jarvis-email-dashboard/.venv/bin/python pruefstand/anker-referenz.py

WOZU: die Faelle in `faelle/` sollen das HEUTIGE Verhalten der Referenz
festhalten, nicht eine Wunschvorstellung. Ohne diesen Anker koennte ich sie so
schreiben, dass mein eigener Port sie besteht — und haette damit nur bewiesen,
dass zwei Dinge von mir zueinander passen.

Deckt die TOKEN-Faelle ab. Die Manifest- und Zustandsfaelle sind in der Referenz
mit Datenbank und HTTP verwoben (`_get_state`/`_set_state` sind SQL) und
deshalb nicht ohne Umbau vergleichbar — genau deswegen ist der Kern hier eine
reine Zustandsmaschine. Was der Anker nicht deckt, sagt er lieber, als es zu
behaupten.

Laeuft er nicht durch, ist zuerst zu entscheiden WER RECHT HAT — und erst danach
etwas zu aendern. Die Faelle passend zu machen waere das Gegenteil einer Messung.
"""

import json, os, pathlib, sys, tempfile
sys.path.insert(0, str(pathlib.Path.home()/"Developer/jarvis-email-dashboard/dashboard"))

FAELLE = pathlib.Path("pruefstand/faelle")
# Die Referenz liest ihren Pubkey aus JARVIS_LICENSE_PUBKEY.
erst = json.loads((FAELLE/"token-gueltig.json").read_text())
pub = erst["eingang"]["pubkey"]
tmp = pathlib.Path(tempfile.mkdtemp())/"pub.pem"; tmp.write_text(pub)
os.environ["JARVIS_LICENSE_PUBKEY"] = str(tmp)

import importlib, license as ref  # noqa: E402
importlib.reload(ref)
from datetime import datetime, timezone  # noqa: E402

# Die Referenz kennt ihr Produkt als Konstante "jarvis-email"; die Faelle nutzen
# "pruef-produkt". Fuer den Vergleich wird die Konstante umgebogen — das ist der
# EINZIGE Eingriff, und er betrifft nicht die Logik.
ref.PRODUCT = "pruef-produkt"

# Abbildung meiner Gruende auf die der Referenz.
UEBERSETZUNG = {"ok": "ok", "fehlt": "missing", "ungueltig": "invalid",
                "falsches_produkt": "wrong_product", "abgelaufen": "expired"}

gut = schlecht = 0
for d in sorted(FAELLE.glob("token-*.json")):
    f = json.loads(d.read_text())
    e, soll = f["eingang"], f["erwartet"]
    jetzt = datetime.fromisoformat(e["jetzt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    st = ref.evaluate(e.get("token") or "", now=jetzt)
    erwartet_ref = UEBERSETZUNG[soll["token_grund"]]
    if st.reason == erwartet_ref and st.valid == soll["token_gueltig"]:
        print(f"  ok   {d.stem:<26} Referenz sagt {st.reason!r}")
        gut += 1
    else:
        print(f"  ✗    {d.stem:<26} Referenz sagt {st.reason!r}/{st.valid}, "
              f"Fall erwartet {erwartet_ref!r}/{soll['token_gueltig']}")
        schlecht += 1
print(f"\n{gut} von {gut+schlecht} Token-Faellen stimmen mit der Referenz ueberein")
sys.exit(1 if schlecht else 0)
