#!/usr/bin/env python3
"""Der Prüfling der Python-Bauart: ein Fall auf stdin, ein Urteil auf stdout.

    echo '<fall.json>' | python3 pruefling.py

Die Schnittstelle ist ABSICHTLICH winzig und sprachneutral. Sie ist das, woran
sich die drei Bauarten messen lassen — nicht ihre inneren Namen, nicht ihre
Signaturen, sondern das Urteil über denselben Eingang.

Fall (Eingang):
    { "pubkey": "<PEM>", "produkt": "…", "token": "<draht>|null",
      "manifest": "<draht>|null", "jetzt": "<ISO>", "karenz_tage": 7,
      "zustand": { "letzter_status": …, "letzte_ok_pruefung": …,
                   "pending_seit": …, "manifest_seq": … } | null }

Urteil (Ausgang):
    { "token_grund": …, "token_gueltig": …, "manifest_status": …,
      "manifest_detail": …, "zustand": {…}, "sperrgrund": … }

Alle Zeitangaben ISO-8601. `null` heisst durchgehend „gibt es nicht" — nicht
„leer" und schon gar nicht „Epoche".
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jarvis_lizenz import (  # noqa: E402
    Zustand, bewerte_manifest, naechster_zustand, pruefe_token, sperrgrund, zeit_lesen,
)


def _iso(d) -> str | None:
    return None if d is None else d.isoformat().replace("+00:00", "Z")


def urteile(fall: dict) -> dict:
    jetzt = zeit_lesen(fall["jetzt"])
    if jetzt is None:
        raise SystemExit("FALL KAPUTT: 'jetzt' ist nicht lesbar")

    tok = pruefe_token(fall.get("token") or "", fall["pubkey"], fall["produkt"], jetzt)

    z_ein = fall.get("zustand")
    alt = None if z_ein is None else Zustand(
        letzter_status=z_ein.get("letzter_status"),
        letzte_ok_pruefung=zeit_lesen(z_ein.get("letzte_ok_pruefung")),
        pending_seit=zeit_lesen(z_ein.get("pending_seit")),
        manifest_seq=z_ein.get("manifest_seq"),
        entitlements=z_ein.get("entitlements"),
    )

    # Das Manifest wird nur bewertet, wenn es eines zu bewerten gibt. `null`
    # heisst „nicht erreichbar" und ist ein gueltiger Eingang — kein Fehler.
    if "manifest" in fall:
        m = bewerte_manifest(fall.get("manifest"), fall["pubkey"],
                             tok.lizenz_id, jetzt, (alt.manifest_seq if alt else None))
        neu = naechster_zustand(alt or Zustand(), m, jetzt)
    else:
        m = None
        neu = alt

    grund = sperrgrund(neu, jetzt, int(fall.get("karenz_tage", 7)), tok.braucht_heartbeat)

    return {
        "token_gueltig": tok.gueltig,
        "token_grund": tok.grund,
        "manifest_status": None if m is None else m.status,
        "manifest_detail": None if m is None else m.detail,
        "zustand": None if neu is None else {
            "letzter_status": neu.letzter_status,
            "letzte_ok_pruefung": _iso(neu.letzte_ok_pruefung),
            "pending_seit": _iso(neu.pending_seit),
            "manifest_seq": neu.manifest_seq,
        },
        "sperrgrund": grund,
    }


if __name__ == "__main__":
    print(json.dumps(urteile(json.load(sys.stdin)), sort_keys=True, ensure_ascii=False))
