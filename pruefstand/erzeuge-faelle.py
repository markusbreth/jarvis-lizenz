#!/usr/bin/env python3
"""Erzeugt die sprachneutralen Prüffälle mit ECHTEN Signaturen.

    python3 pruefstand/erzeuge-faelle.py

Warum erzeugt und nicht von Hand geschrieben: die Fälle tragen signierte
Artefakte. Von Hand hiesse, Signaturen zu kopieren — und beim nächsten Feld ist
keine mehr gültig. Erzeugt heisst: eine Zeile ändern, neu laufen lassen.

Der Schlüssel ist ein WEGWERF-PAAR, fest eingebaut. Es darf im Repo stehen: es
signiert nichts Echtes, und die Fälle müssen ohne Vorbereitung reproduzierbar
sein. Ein zufälliges Paar bei jedem Lauf würde die Fälle bei jedem Aufruf
ändern und den Vergleich über die Zeit unmöglich machen.

WAS DIE FÄLLE SIND UND WAS NICHT: sie halten das Verhalten der Referenz fest
(jarvis-email-dashboard), nicht eine Wunschvorstellung. Wo eine Bauart abweicht,
ist sie rot — nicht der Fall. Wo die REFERENZ abweicht, ist erst zu entscheiden,
wer recht hat.
"""
import json
import pathlib
import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HIER = pathlib.Path(__file__).resolve().parent
ZIEL = HIER / "faelle"

# Wegwerf-Schlüsselpaar, fest. Siehe Kopf: Reproduzierbarkeit vor Zufall.
SEED = bytes(range(32))
PRIV = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
# Ein zweites Paar, um „fremd signiert" zu bauen.
FREMD = Ed25519PrivateKey.from_private_bytes(bytes(range(100, 132)))

PRODUKT = "pruef-produkt"
LIZENZ = "lic-1"
JETZT = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.isoformat().replace("+00:00", "Z")


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def draht(nutzlast: dict, key=PRIV) -> str:
    roh = json.dumps(nutzlast, sort_keys=True, separators=(",", ":")).encode()
    return b64(roh) + "." + b64(key.sign(roh))


def token(**over) -> str:
    p = {
        "product": PRODUKT, "customer": "Prüfkunde", "license_id": LIZENZ,
        "issued_at": iso(JETZT - timedelta(days=30)),
        "expires_at": iso(JETZT + timedelta(days=365)),
        "features": ["all"], "require_heartbeat": True,
        "license_server": "https://example.invalid/m.jws",
        "ping_url": "https://example.invalid",
    }
    p.update(over)
    return draht(p)


def manifest(key=PRIV, **over) -> str:
    m = {
        "type": "license-manifest", "product": PRODUKT,
        "issued_at": iso(JETZT - timedelta(hours=1)),
        "valid_until": iso(JETZT + timedelta(hours=71)),
        "revoked": [], "licenses": {LIZENZ: {"features": ["all"], "limits": {}}},
        "seq": 10,
    }
    m.update(over)
    return draht(m, key)


def zustand(**over):
    z = {"letzter_status": None, "letzte_ok_pruefung": None,
         "pending_seit": None, "manifest_seq": None}
    z.update(over)
    return z


def fall(name, beschreibung, warum, erwartet, **fall_felder):
    f = {
        "name": name,
        "beschreibung": beschreibung,
        "warum": warum,
        "eingang": {"pubkey": fall_felder.pop("pubkey_ersatz", PUB),
                    "produkt": PRODUKT, "jetzt": iso(JETZT),
                    "karenz_tage": 7, **fall_felder},
        "erwartet": erwartet,
    }
    (ZIEL / f"{name}.json").write_text(
        json.dumps(f, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return name


def u(token_gueltig, token_grund, manifest_status=None, manifest_detail=None,
      sperrgrund=None, zust=None):
    return {"token_gueltig": token_gueltig, "token_grund": token_grund,
            "manifest_status": manifest_status, "manifest_detail": manifest_detail,
            "sperrgrund": sperrgrund, "zustand": zust}


ZIEL.mkdir(exist_ok=True)
for alt in ZIEL.glob("*.json"):
    alt.unlink()
namen = []

# ── Das Token ────────────────────────────────────────────────────────────────
namen.append(fall(
    "token-gueltig",
    "Ein frisches, richtig signiertes Token für dieses Produkt",
    "Der Gutfall. Ohne ihn wäre nicht zu unterscheiden, ob eine Bauart prüft "
    "oder pauschal ablehnt.",
    u(True, "ok"), token=token()))

namen.append(fall(
    "token-fehlt",
    "Gar kein Token",
    "Muss `fehlt` heissen und nicht `ungueltig` — das Produkt zeigt darauf eine "
    "andere Oberfläche (Ersteinrichtung statt Fehler).",
    u(False, "fehlt"), token=None))

namen.append(fall(
    "token-verfaelscht",
    "Ein Zeichen der Nutzlast verändert, Signatur unverändert",
    "Die Signatur ist der ganze Schutz. Fällt dieser Fall nicht auf, prüft die "
    "Bauart gar nicht.",
    u(False, "ungueltig"),
    token=(lambda t: t[:20] + ("B" if t[20] != "B" else "C") + t[21:])(token())))

namen.append(fall(
    "token-fremd-signiert",
    "Richtig gebaut, aber mit einem anderen Schlüssel signiert",
    "Der Fall, den ein Kunde bauen würde, der sich selbst eine Lizenz ausstellt "
    "— genau der Befund von Hotel OS am 28.08.2026.",
    u(False, "ungueltig"),
    token=draht({"product": PRODUKT, "license_id": LIZENZ,
                 "expires_at": None, "require_heartbeat": True}, FREMD)))

namen.append(fall(
    "token-falsches-produkt",
    "Gültig signiert, aber für ein anderes Produkt ausgestellt",
    "Heute fängt das schon die Signatur ab (jedes Produkt hat ein eigenes Paar). "
    "Der Wächter ist der zweite Riemen — für den Tag, an dem jemand die Paare "
    "zusammenlegt.",
    u(False, "falsches_produkt"), token=token(product="ein-anderes")))

namen.append(fall(
    "token-ohne-produktfeld",
    "Ein Token aus der Zeit vor der Console — ohne `product`",
    "Muss GÜLTIG bleiben. Die abgelöste gen-license.py schrieb das Feld nie; "
    "eine strenge Prüfung legte eine laufende Installation lahm.",
    u(True, "ok"),
    token=draht({"customer": "Alt", "license_id": LIZENZ, "expires_at": None,
                 "require_heartbeat": False})))

namen.append(fall(
    "token-abgelaufen",
    "Ablaufdatum liegt in der Vergangenheit",
    "Rein offline entschieden, ohne Netz und ohne Manifest.",
    u(False, "abgelaufen"), token=token(expires_at=iso(JETZT - timedelta(days=1)))))

namen.append(fall(
    "token-unbefristet",
    "`expires_at: null`",
    "Null heisst unbefristet, nicht „abgelaufen am 1.1.1970\". Die Verwechslung "
    "von „gibt es nicht\" mit „Epoche\" hat im Maschinenraum zweimal einen roten "
    "Fehlalarm erzeugt.",
    u(True, "ok"), token=token(expires_at=None)))

namen.append(fall(
    "pubkey-kaputt",
    "Der Prüfschlüssel selbst ist unlesbar (beschädigte oder leere PEM-Datei)",
    "DIESER FALL HAT GEFEHLT, und die Lücke war real: JS und Go fingen einen "
    "kaputten Schlüssel als `ungueltig` ab, Python liess den rohen ValueError "
    "durch — beim Aufrufer ein 500 statt eines 403. Von den fünf Produkten "
    "hatte nur BauKI die Härtung, und dessen eigener Test hat sie gefunden. "
    "Ein Prüfstand ohne diesen Fall bescheinigt drei Bauarten Einigkeit, die "
    "sie nicht haben.",
    u(False, "ungueltig"),
    token=token(), pubkey_ersatz="-----BEGIN PUBLIC KEY-----\nMUELL\n-----END PUBLIC KEY-----"))

# ── Das Manifest ─────────────────────────────────────────────────────────────
namen.append(fall(
    "manifest-aktiv",
    "Frisches Manifest, Lizenz aufgeführt, kein Widerruf",
    "Der Gutfall der Online-Seite: er setzt `letzte_ok_pruefung` und löscht "
    "`pending_seit`.",
    u(True, "ok", "aktiv", "ok", None,
      zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT), manifest_seq=10)),
    token=token(), manifest=manifest(), zustand=None))

namen.append(fall(
    "manifest-widerrufen",
    "Die Lizenz steht in `revoked[]`",
    "Der Notaus. Nur ein AUSDRÜCKLICHER Eintrag sperrt.",
    u(True, "ok", "widerrufen", "widerrufen", "widerrufen",
      zustand(letzter_status="widerrufen", pending_seit=iso(JETZT), manifest_seq=10)),
    token=token(), manifest=manifest(revoked=[LIZENZ]), zustand=None))

namen.append(fall(
    "manifest-nicht-aufgefuehrt",
    "Gültig signiert, aber die Lizenz fehlt in `licenses{}` — und steht auch "
    "nicht in `revoked[]`",
    "HÄRTUNG 3: Abwesenheit ist NICHT maßgeblich. Ein unvollständiges oder "
    "seitenweise ausgeliefertes Manifest darf keinen zahlenden Kunden lahmlegen. "
    "Muss `unbekannt` sein, nicht `widerrufen` — Hotel OS macht hier bis heute "
    "das Gegenteil.",
    u(True, "ok", "unbekannt", "nicht_aufgefuehrt", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT), manifest_seq=10)),
    token=token(), manifest=manifest(licenses={"jemand-anderes": {}}), zustand=None))

namen.append(fall(
    "manifest-unerreichbar",
    "Kein Manifest abrufbar (Netz, DNS, Zeitüberschreitung)",
    "Die häufigste Störung überhaupt. Sie darf nie sperren — nur die Karenzzeit "
    "auslösen.",
    u(True, "ok", "unbekannt", "unerreichbar", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT))),
    token=token(), manifest=None, zustand=None))

namen.append(fall(
    "manifest-fremd-signiert",
    "Manifest mit einem anderen Schlüssel signiert",
    "Muss `unbekannt` sein, nicht „ignorieren\" und nicht „sperren\". Ein "
    "gefälschtes Manifest darf weder wirken noch den Betrieb anhalten.",
    u(True, "ok", "unbekannt", "signatur_falsch", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT))),
    token=token(), manifest=manifest(FREMD, revoked=[LIZENZ]), zustand=None))

namen.append(fall(
    "manifest-veraltet",
    "`valid_until` liegt in der Vergangenheit",
    "Frischegrenze, kein Ablaufdatum: ein alter Stand gilt wie NICHT ERREICHBAR. "
    "Sonst könnte ein Kunde ein Manifest einfrieren, um einem Widerruf zu "
    "entgehen — deshalb darf ein veraltetes Manifest auch keinen Widerruf mehr "
    "tragen.",
    u(True, "ok", "unbekannt", "veraltet", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT))),
    token=token(), manifest=manifest(valid_until=iso(JETZT - timedelta(hours=1)),
                                     revoked=[LIZENZ]), zustand=None))

namen.append(fall(
    "manifest-rueckrollung",
    "Manifest mit kleinerer `seq` als die zuletzt angenommene",
    "Ein alter Stand darf einen Widerruf nicht zurücknehmen. Der Hochstand sinkt "
    "dabei NICHT.",
    u(True, "ok", "unbekannt", "rueckrollung", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT), manifest_seq=10)),
    token=token(), manifest=manifest(seq=5), zustand=zustand(manifest_seq=10)))

namen.append(fall(
    "manifest-kein-manifest",
    "Gültig signiert, aber es ist ein Lizenz-Token statt eines Manifests",
    "Ein verwechselter `license_server` darf nicht als leeres Manifest gelten — "
    "sonst wäre jede Lizenz „nicht aufgeführt\" und liefe in die Karenz.",
    u(True, "ok", "unbekannt", "kein_manifest", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT))),
    token=token(), manifest=token(), zustand=None))

# ── Die Härtungen im Zustand ────────────────────────────────────────────────
namen.append(fall(
    "widerruf-klebt",
    "Bestätigter Widerruf, danach ein `unbekannt` (Netz gekappt)",
    "HÄRTUNG 2: der Widerruf KLEBT. Ohne sie „ent-widerruft\" das Ziehen des "
    "Netzsteckers die Lizenz für die ganze Karenzzeit — der billigste Angriff "
    "auf den Notaus, den es gibt.",
    u(True, "ok", "unbekannt", "unerreichbar", "widerrufen",
      zustand(letzter_status="widerrufen", pending_seit=iso(JETZT - timedelta(days=1)),
              manifest_seq=10)),
    token=token(), manifest=None,
    zustand=zustand(letzter_status="widerrufen",
                    pending_seit=iso(JETZT - timedelta(days=1)), manifest_seq=10)))

namen.append(fall(
    "widerruf-wird-durch-aktiv-geloest",
    "Bestätigter Widerruf, danach ein frisches `aktiv`",
    "DIE GEGENPROBE zu `widerruf-klebt`. Klebte er auch hier, wäre ein "
    "zurückgenommener Widerruf unumkehrbar und der Kunde für immer gesperrt.",
    u(True, "ok", "aktiv", "ok", None,
      zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT), manifest_seq=11)),
    token=token(), manifest=manifest(seq=11),
    zustand=zustand(letzter_status="widerrufen",
                    pending_seit=iso(JETZT - timedelta(days=1)), manifest_seq=10)))

namen.append(fall(
    "karenz-tag-1-noch-nie-geprueft",
    "Noch nie erfolgreich geprüft, seit 1 Tag Fehlversuche",
    "Innerhalb der Karenz: läuft weiter. Ein gerade aufgesetzter Kunde mit "
    "wackligem Netz darf nicht am ersten Tag stehen.",
    u(True, "ok", "unbekannt", "unerreichbar", None,
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=1)))),
    token=token(), manifest=None,
    zustand=zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=1)))))

namen.append(fall(
    "karenz-tag-8-noch-nie-geprueft",
    "Noch nie erfolgreich geprüft, seit 8 Tagen Fehlversuche (Karenz 7)",
    "HÄRTUNG 1: gezählt wird ab dem STABILEN Anker `pending_seit`. Würde ab "
    "„zuletzt versucht\" gezählt, schöbe jeder Fehlversuch die Frist vor sich her "
    "und sie liefe nie ab.",
    u(True, "ok", "unbekannt", "unerreichbar", "pruefung_ueberfaellig",
      zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=8)))),
    token=token(), manifest=None,
    zustand=zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=8)))))

namen.append(fall(
    "karenz-tag-6-nach-erfolg",
    "Zuletzt vor 6 Tagen erfolgreich geprüft (Karenz 7)",
    "Innerhalb der Karenz nach einem Erfolg — der Normalfall eines Kunden, der "
    "übers Wochenende offline war.",
    u(True, "ok", None, None, None,
      zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=6)))),
    token=token(),
    zustand=zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=6)))))

namen.append(fall(
    "karenz-tag-8-nach-erfolg",
    "Zuletzt vor 8 Tagen erfolgreich geprüft (Karenz 7)",
    "Jenseits der Karenz: gesperrt. Das Paar 6/8 ist der eigentliche Beweis — "
    "eine Schwelle, die immer sperrt oder nie, sieht in einem einzelnen Fall "
    "genauso aus wie eine, die misst.",
    u(True, "ok", None, None, "pruefung_ueberfaellig",
      zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=8)))),
    token=token(),
    zustand=zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=8)))))

namen.append(fall(
    "ohne-require-heartbeat-kein-widerruf",
    "Token ohne `require_heartbeat`, Manifest widerruft die Lizenz",
    "DIE TEUERSTE LEHRE DES PROJEKTS. Eine Kundenlizenz lief fünf Wochen mit "
    "`require_heartbeat: false`: Gate scharf, Manifest frisch — und der Widerruf "
    "wirkungslos, ohne dass irgendwo etwas fehlschlug. Von aussen sieht dieser "
    "Zustand exakt aus wie ein funktionierender Notaus. Der Fall hält fest, dass "
    "das ABSICHT ist und kein Fehler: die Politik steckt im signierten Token.",
    u(True, "ok", "widerrufen", "widerrufen", None,
      zustand(letzter_status="widerrufen", pending_seit=iso(JETZT), manifest_seq=10)),
    token=token(require_heartbeat=False), manifest=manifest(revoked=[LIZENZ]), zustand=None))

namen.append(fall(
    "frisch-gestartet-sperrt-nicht",
    "`require_heartbeat`, aber noch kein Zustand vorhanden",
    "Ein gerade gestarteter Dienst wird nicht gesperrt. Sonst sperrte jeder "
    "Neustart, bis der erste Lauf durch ist — und ein Neustart ist genau das, "
    "was jemand tut, wenn etwas klemmt.",
    u(True, "ok", None, None, None, None),
    token=token(), zustand=None))

# ── Seit 0.2.0: Kunden-Modus, Bindung, Offline, Hochwassermarke ──────────────
# Diese Fälle tragen `erweitert: true` und erwarten zusätzlich `erweiterung`.
# Die Fälle darüber bleiben, wie sie in 0.1 waren — sie sind der Beleg, dass
# 0.2.0 nichts an ihnen ändert.


def ue(basis, bindung=None, offline=False, zurueckgestellt=False):
    return {**basis, "erweiterung": {"bindung": bindung, "offline": offline,
                                     "uhr_zurueckgestellt": zurueckgestellt}}


def efall(name, beschreibung, warum, erwartet, **felder):
    return fall(name, beschreibung, warum, erwartet, erweitert=True, **felder)


namen.append(efall(
    "kunden-modus-ohne-zustand-nach-karenz",
    "Kunden-Modus, kein Zustand, Token vor 30 Tagen ausgestellt (Karenz 7)",
    "LÜCKE G1 DER 0.1: ein gelöschter Zustand hiess „frisch gestartet“ und "
    "sperrte nie — ein SQL-DELETE schaltete den Fern-Widerruf ab. Im "
    "Kunden-Modus zählt die Karenz ab `issued_at`. Gegenstück ohne "
    "Kunden-Modus: frisch-gestartet-sperrt-nicht.",
    ue(u(True, "ok", None, None, "pruefung_ueberfaellig", None)),
    token=token(), zustand=None, kunden_modus=True))

namen.append(efall(
    "kunden-modus-ohne-zustand-in-karenz",
    "Kunden-Modus, kein Zustand, Token vor 3 Tagen ausgestellt (Karenz 7)",
    "Das Paar zu 30 Tagen: eine frische Installation läuft, bis der erste "
    "Heartbeat durch ist. Eine Schwelle, die immer sperrt, sähe im Fall davor "
    "genauso aus.",
    ue(u(True, "ok", None, None, None, None)),
    token=token(issued_at=iso(JETZT - timedelta(days=3))), zustand=None, kunden_modus=True))

namen.append(efall(
    "leerer-zustand-ohne-kunden-modus",
    "Zustand ohne beide Anker, kein Kunden-Modus",
    "Hält das Verhalten der 0.1 fest: ein Zustand ohne `letzte_ok_pruefung` und "
    "ohne `pending_seit` sperrt nie. Das ist die Lücke, die der Kunden-Modus "
    "schliesst — Gegenstück: kunden-modus-leerer-zustand.",
    ue(u(True, "ok", None, None, None, zustand(letzter_status="aktiv"))),
    token=token(), zustand=zustand(letzter_status="aktiv")))

namen.append(efall(
    "kunden-modus-leerer-zustand",
    "Kunden-Modus, Zustand ohne beide Anker, Token vor 30 Tagen ausgestellt",
    "Wer statt der Zeile nur die Zeitstempel löscht, bekommt dasselbe wie beim "
    "Löschen der Zeile: Karenz ab `issued_at`.",
    ue(u(True, "ok", None, None, "pruefung_ueberfaellig", zustand(letzter_status="aktiv"))),
    token=token(), zustand=zustand(letzter_status="aktiv"), kunden_modus=True))

namen.append(efall(
    "kunden-modus-ohne-anker",
    "Kunden-Modus, kein Zustand, Token ohne `issued_at`",
    "Ohne Zustand und ohne Anker gibt es nichts, ab dem gezählt werden kann. "
    "Der Kunden-Modus sperrt dann sofort, statt nie.",
    ue(u(True, "ok", None, None, "pruefung_ueberfaellig", None)),
    token=token(issued_at=None), zustand=None, kunden_modus=True))

namen.append(efall(
    "kunden-modus-widerruf-ohne-anker",
    "Kunden-Modus, Zustand `widerrufen` ohne Zeitstempel",
    "Ein Widerruf klebt auch dann, wenn die Zeitstempel fehlen — der "
    "Kunden-Modus darf aus `widerrufen` kein „Karenz ab issued_at“ machen.",
    ue(u(True, "ok", None, None, "widerrufen", zustand(letzter_status="widerrufen"))),
    token=token(issued_at=iso(JETZT - timedelta(days=1))),
    zustand=zustand(letzter_status="widerrufen"), kunden_modus=True))

namen.append(efall(
    "kunden-modus-mit-zustand-wie-bisher",
    "Kunden-Modus, zuletzt vor 6 Tagen erfolgreich geprüft, Token 30 Tage alt",
    "Mit einem Zustand rechnet der Kunden-Modus genau wie 0.1 — sonst sperrte "
    "er jede Installation, deren Token älter als die Karenz ist.",
    ue(u(True, "ok", None, None, None,
         zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=6))))),
    token=token(),
    zustand=zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT - timedelta(days=6))),
    kunden_modus=True))

namen.append(efall(
    "kunden-modus-ohne-heartbeat",
    "Kunden-Modus, Token ohne `require_heartbeat`, kein Zustand",
    "Die Politik steckt weiter im signierten Token: ohne Heartbeat gibt es "
    "nichts zu prüfen, auch im Kunden-Modus. Ein Einmal-Kauf ohne Heartbeat "
    "stellt man deshalb gar nicht erst aus.",
    ue(u(True, "ok", None, None, None, None)),
    token=token(require_heartbeat=False), zustand=None, kunden_modus=True))

namen.append(efall(
    "bindung-ok",
    "Token an `inst-1` gebunden, Installation ist `inst-1`",
    "Der Gutfall der Bindung. Ohne ihn wäre nicht zu unterscheiden, ob eine "
    "Bauart vergleicht oder pauschal ablehnt.",
    ue(u(True, "ok"), bindung="ok"),
    token=token(install_id="inst-1"), install_id="inst-1"))

namen.append(efall(
    "bindung-fremd",
    "Token an `inst-1` gebunden, Installation ist `inst-2`",
    "LÜCKE G3 DER 0.1: ein Token lief auf beliebig vielen Installationen. Die "
    "Bindung ist ein eigenes Urteil — was bei `fremd` passiert, entscheidet das "
    "Produkt; die Gültigkeit des Tokens bleibt unberührt.",
    ue(u(True, "ok"), bindung="fremd"),
    token=token(install_id="inst-1"), install_id="inst-2"))

namen.append(efall(
    "bindung-installation-ohne-kennung",
    "Token gebunden, die Installation kennt ihre Kennung nicht",
    "Wer seine Kennung verliert (gelöscht, nie erzeugt), darf nicht als "
    "passend durchgehen — sonst wäre Löschen der Weg um die Bindung.",
    ue(u(True, "ok"), bindung="fremd"),
    token=token(install_id="inst-1"), install_id=None))

namen.append(efall(
    "bindung-ungebunden",
    "Token ohne `install_id`, Installation `inst-1`",
    "Altbestand und absichtlich ungebundene Tokens: der Kern sagt `ungebunden`, "
    "nicht `fremd` — sonst bräche jedes Token, das vor 0.2.0 ausgestellt wurde.",
    ue(u(True, "ok"), bindung="ungebunden"),
    token=token(), install_id="inst-1"))

namen.append(efall(
    "offline-mit-ablauf",
    "Offline-Token mit Ablauf in einem Jahr",
    "Die ausdrücklich ausgestellte Offline-Lizenz: gültig, als offline erkannt.",
    ue(u(True, "ok"), offline=True),
    token=token(offline=True, require_heartbeat=False)))

namen.append(efall(
    "offline-ohne-ablauf",
    "Offline-Token ohne Ablauf",
    "Kein Offline-Perpetual: ohne Heartbeat und ohne Ablauf schützte nur noch "
    "der Vertrag. Gegenstück: token-unbefristet (ohne `offline`) bleibt gültig.",
    ue(u(False, "offline_ohne_ablauf"), offline=True),
    token=token(offline=True, require_heartbeat=False, expires_at=None)))

namen.append(efall(
    "uhr-zurueckgestellt",
    "Token gestern abgelaufen, Uhr um 10 Tage zurückgestellt, Marke = heute",
    "LÜCKE G2 DER 0.1: die Uhr zurückzustellen verlängerte Ablauf und Karenz. "
    "Mit der Hochwassermarke rechnet der Kern ab der Marke und meldet die "
    "Rückstellung. Gegenstück ohne Marke: uhr-zurueckgestellt-ohne-marke.",
    ue(u(False, "abgelaufen"), zurueckgestellt=True),
    token=token(expires_at=iso(JETZT - timedelta(days=1))),
    jetzt=iso(JETZT - timedelta(days=10)), uhr_marke=iso(JETZT)))

namen.append(efall(
    "uhr-zurueckgestellt-ohne-marke",
    "Dasselbe Token, dieselbe zurückgestellte Uhr, keine Marke",
    "Hält fest, was ohne Marke passiert: das abgelaufene Token gilt wieder. "
    "Dieser Fall ist die Lücke, nicht das Soll.",
    ue(u(True, "ok")),
    token=token(expires_at=iso(JETZT - timedelta(days=1))),
    jetzt=iso(JETZT - timedelta(days=10))))

namen.append(efall(
    "uhr-vor-der-marke",
    "Uhr steht nach der Marke",
    "Der Normalfall: die Uhr läuft vorwärts, die Marke ist älter. Nichts wird "
    "gemeldet, gerechnet wird mit der Uhr.",
    ue(u(True, "ok")),
    token=token(), uhr_marke=iso(JETZT - timedelta(days=1))))

print(f"{len(namen)} Fälle geschrieben nach {ZIEL}")
for n in sorted(namen):
    print("  ", n)
