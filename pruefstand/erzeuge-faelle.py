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


def pem(priv) -> str:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# Seit 0.2.0: der NÄCHSTE Hauptschlüssel (Rotation) und der Erneuerungsschlüssel
# des Lizenzdienstes. Der Ring ist, was ein Image mitbringt: aktuell + nächster.
NAECHST = Ed25519PrivateKey.from_private_bytes(bytes(range(40, 72)))
ERNEUERUNG = Ed25519PrivateKey.from_private_bytes(bytes(range(200, 232)))
RING = {"k1": PUB, "k2": pem(NAECHST)}

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


def _nutzlast(d: str) -> str:
    return base64.urlsafe_b64decode(d.split(".")[0] + "==").decode()


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

namen.append(efall(
    "kunden-modus-geloescht-und-server-gesperrt",
    "Kunden-Modus, Zustand gelöscht, Lizenzserver nicht erreichbar, Token 30 Tage alt",
    "BEFUND DER DURCHSICHT 27.10.: der normale Ablauf ruft erst naechster_zustand, "
    "der `pending_seit` auf „jetzt“ setzt — zählte der Kunden-Modus nur ohne "
    "Anker ab `issued_at`, schenkten Löschen plus Blockieren des Servers eine "
    "frische Karenz, beliebig oft. Gezählt wird ab dem früheren der beiden. "
    "Gegenstück: geloescht-und-server-gesperrt-ohne-kunden-modus.",
    ue(u(True, "ok", "unbekannt", "unerreichbar", "pruefung_ueberfaellig",
         zustand(letzter_status="unbekannt", pending_seit=iso(JETZT)))),
    token=token(), manifest=None, zustand=None, kunden_modus=True))

namen.append(efall(
    "geloescht-und-server-gesperrt-ohne-kunden-modus",
    "Wie davor, ohne Kunden-Modus",
    "Hält fest, was 0.1 hier tut: die Karenz beginnt neu. Das ist die Lücke, "
    "nicht das Soll.",
    ue(u(True, "ok", "unbekannt", "unerreichbar", None,
         zustand(letzter_status="unbekannt", pending_seit=iso(JETZT)))),
    token=token(), manifest=None, zustand=None))

namen.append(efall(
    "kunden-modus-pending-frueher-als-anker",
    "Kunden-Modus, Token 3 Tage alt, seit 10 Tagen erfolglos",
    "Ist `pending_seit` älter als `issued_at`, zählt `pending_seit` — ein neu "
    "ausgestelltes Token setzt eine laufende Frist nicht zurück.",
    ue(u(True, "ok", None, None, "pruefung_ueberfaellig",
         zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=10))))),
    token=token(issued_at=iso(JETZT - timedelta(days=3))),
    zustand=zustand(letzter_status="unbekannt", pending_seit=iso(JETZT - timedelta(days=10))),
    kunden_modus=True))

namen.append(efall(
    "kunden-modus-genau-an-der-grenze",
    "Kunden-Modus, kein Zustand, Token genau 7 Tage alt (Karenz 7)",
    "Die Grenze selbst sperrt noch nicht (`>`, nicht `>=`) — wie bei "
    "`letzte_ok_pruefung` in 0.1.",
    ue(u(True, "ok", None, None, None, None)),
    token=token(issued_at=iso(JETZT - timedelta(days=7))), zustand=None, kunden_modus=True))

namen.append(efall(
    "kunden-modus-ok-in-der-zukunft",
    "Kunden-Modus, `letzte_ok_pruefung` 30 Tage in der Zukunft, Token 30 Tage alt",
    "Ein Erfolg aus der Zukunft ist kein Erfolg — sonst sperrte ein von Hand "
    "gesetzter Zeitstempel nie. Gezählt wird dann ab `issued_at`.",
    ue(u(True, "ok", None, None, "pruefung_ueberfaellig",
         zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT + timedelta(days=30))))),
    token=token(),
    zustand=zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT + timedelta(days=30))),
    kunden_modus=True))

namen.append(efall(
    "bindung-zahl-im-token",
    "Token mit `install_id: 1` (Zahl), Installation „1“",
    "Nur eine Zeichenkette bindet. Eine Zahl schreibt jede Sprache anders als "
    "Text (1 · 1.0 · 1e21) — die Bauarten kämen zu verschiedenen Urteilen.",
    ue(u(True, "ok"), bindung="fremd"),
    token=token(install_id=1), install_id="1"))

# ── Seit 0.2.0: Schlüsselring (kid) und Erneuerungskette ─────────────────────
# Die Namen beginnen absichtlich NICHT mit `token-`: anker-referenz.py vergleicht
# genau diese Fälle mit der Referenz von 0.1, und die kennt weder Ring noch Kette.


def berechtigung(key=PRIV, **over) -> str:
    b = {
        "type": "erneuerungs-berechtigung", "product": PRODUKT, "kid": "k1",
        "renew_kid": "e1", "pubkey": pem(ERNEUERUNG),
        "issued_at": iso(JETZT - timedelta(days=60)),
        "expires_at": iso(JETZT + timedelta(days=300)),
        "max_token_tage": 31,
    }
    b.update(over)
    return draht(b, key)


def erneuert(key=ERNEUERUNG, **over) -> str:
    """Ein Token, wie der Lizenzdienst es ausstellt: 30 Tage, gebunden."""
    p = {
        "product": PRODUKT, "customer": "Prüfkunde", "license_id": LIZENZ,
        "issued_at": iso(JETZT - timedelta(days=3)),
        "expires_at": iso(JETZT + timedelta(days=27)),
        "features": ["all"], "require_heartbeat": True, "install_id": "inst-1",
        "license_server": "https://example.invalid/m.jws",
        "berechtigung": berechtigung(),
    }
    p.update(over)
    return draht(p, key)


namen.append(efall(
    "ring-kid-aktuell",
    "Token mit `kid: k1`, Ring {k1, k2}",
    "Der Gutfall des Rings: das `kid` wählt den Schlüssel.",
    ue(u(True, "ok")), token=token(kid="k1"), pubkey_ersatz=RING))

namen.append(efall(
    "ring-kid-naechster",
    "Token mit `kid: k2`, vom nächsten Schlüssel signiert, Ring {k1, k2}",
    "ROTATION (N4): ein Image, das den nächsten Schlüssel schon trägt, nimmt "
    "neue Tokens an, bevor der alte Schlüssel abgelöst ist. Mit "
    "ring-kid-aktuell zusammen: altes und neues Token gelten beide.",
    ue(u(True, "ok")), token=draht({"product": PRODUKT, "customer": "Prüfkunde", "license_id": LIZENZ,
           "issued_at": iso(JETZT - timedelta(days=30)),
           "expires_at": iso(JETZT + timedelta(days=365)),
           "features": ["all"], "require_heartbeat": True, "kid": "k2"}, NAECHST),
    pubkey_ersatz=RING))

namen.append(efall(
    "ring-ohne-kid",
    "Token ohne `kid` (Altbestand), Ring {k1, k2}",
    "Tokens von vor 0.2.0 tragen kein `kid`. Sie müssen gegen den Ring gültig "
    "bleiben — sonst sperrte das erste Image mit Ring jede laufende Lizenz.",
    ue(u(True, "ok")), token=token(), pubkey_ersatz=RING))

namen.append(efall(
    "kid-unbekannt",
    "Token mit `kid: k9`, das im Ring nicht steht",
    "Abgelehnt, und zwar mit eigenem Grund: `schluessel_unbekannt` heisst „das "
    "Image ist älter als der Schlüssel“, nicht „gefälscht“. Der Betreiber sieht "
    "so, dass ein Update fehlt.",
    ue(u(False, "schluessel_unbekannt")), token=token(kid="k9"), pubkey_ersatz=RING))

namen.append(efall(
    "kid-falscher-schluessel",
    "Token nennt `kid: k2`, ist aber mit k1 signiert",
    "Das `kid` bindet: mit Ring wird NUR der genannte Schlüssel versucht. "
    "Probierte die Bauart alle, wäre das `kid` Dekoration.",
    ue(u(False, "ungueltig")), token=token(kid="k2"), pubkey_ersatz=RING))

namen.append(efall(
    "ring-fremd-signiert",
    "Token ohne `kid`, fremd signiert, Ring {k1, k2}",
    "Ohne `kid` darf jeder Schlüssel des Rings passen — aber nur einer des "
    "Rings. Das Gegenstück zu ring-ohne-kid.",
    ue(u(False, "ungueltig")),
    token=draht({"product": PRODUKT, "license_id": LIZENZ, "expires_at": None,
                 "require_heartbeat": True}, FREMD), pubkey_ersatz=RING))

namen.append(efall(
    "kid-mit-einzelschluessel",
    "Token mit `kid: k1`, Aufrufer übergibt ein einzelnes PEM",
    "Ein Produkt auf 0.1-Art (ein PEM) liest neue Tokens weiter: das `kid` "
    "wird ohne Ring nicht gelesen.",
    ue(u(True, "ok")), token=token(kid="k1")))

namen.append(efall(
    "kette-gueltig",
    "Token vom Erneuerungsschlüssel, mit gültiger Berechtigung, 30 Tage, Ring",
    "Der Gutfall der Erneuerungskette (Schicht C): der Lizenzdienst stellt "
    "kurze Tokens aus, ohne den Hauptschlüssel zu kennen.",
    ue(u(True, "ok")), token=erneuert(), pubkey_ersatz=RING))

namen.append(efall(
    "kette-mit-einzelschluessel",
    "Dieselbe Kette, Aufrufer übergibt ein einzelnes PEM",
    "Die Berechtigung wird mit dem Hauptschlüssel geprüft, egal ob er als Ring "
    "oder als PEM kommt.",
    ue(u(True, "ok")), token=erneuert()))

namen.append(efall(
    "kette-ohne-berechtigung",
    "Token vom Erneuerungsschlüssel, OHNE Berechtigung",
    "Der Erneuerungsschlüssel allein ist nichts wert: ohne die vom "
    "Hauptschlüssel signierte Berechtigung ist er ein fremder Schlüssel.",
    ue(u(False, "ungueltig")),
    token=draht({k: v for k, v in __import__("json").loads(
        _nutzlast(erneuert())).items() if k != "berechtigung"}, ERNEUERUNG),
    pubkey_ersatz=RING))

namen.append(efall(
    "kette-berechtigung-fremd-signiert",
    "Berechtigung nicht vom Hauptschlüssel, sondern fremd signiert",
    "Wer sich selbst eine Berechtigung ausstellt, stellt sich selbst Lizenzen aus.",
    ue(u(False, "ungueltig")), token=erneuert(berechtigung=berechtigung(FREMD)),
    pubkey_ersatz=RING))

namen.append(efall(
    "kette-berechtigung-kid-unbekannt",
    "Berechtigung nennt ein `kid`, das im Ring nicht steht",
    "Dieselbe Regel wie beim Token: das `kid` der Berechtigung wählt den "
    "Hauptschlüssel.",
    ue(u(False, "schluessel_unbekannt")),
    token=erneuert(berechtigung=berechtigung(kid="k9")), pubkey_ersatz=RING))

namen.append(efall(
    "kette-fremder-erneuerungsschluessel",
    "Berechtigung gültig, Token aber nicht vom berechtigten Schlüssel signiert",
    "Die Berechtigung nennt GENAU EINEN Schlüssel. Eine echte Berechtigung an "
    "ein selbst signiertes Token zu hängen, darf nichts nützen — die "
    "Berechtigung ist öffentlich, sie steckt in jedem erneuerten Token.",
    ue(u(False, "ungueltig")), token=erneuert(key=FREMD), pubkey_ersatz=RING))

namen.append(efall(
    "kette-falsches-produkt",
    "Berechtigung für ein anderes Produkt",
    "Ein Erneuerungsschlüssel ist je Produkt berechtigt.",
    ue(u(False, "falsches_produkt")),
    token=erneuert(berechtigung=berechtigung(product="ein-anderes")), pubkey_ersatz=RING))

namen.append(efall(
    "kette-berechtigung-ueber-ein-jahr",
    "Berechtigung 400 Tage gültig",
    "Eine Berechtigung gilt höchstens 366 Tage — der Kern setzt das durch, "
    "nicht die Console. Ein Fehler beim Ausstellen soll keinen Dauerschlüssel "
    "erzeugen.",
    ue(u(False, "berechtigung_ungueltig")),
    token=erneuert(berechtigung=berechtigung(expires_at=iso(JETZT + timedelta(days=340)))),
    pubkey_ersatz=RING))

namen.append(efall(
    "kette-berechtigung-ohne-laufzeit",
    "Berechtigung ohne `max_token_tage`",
    "Ohne erlaubte Laufzeit gibt es keine Obergrenze — also keine Berechtigung.",
    ue(u(False, "berechtigung_ungueltig")),
    token=erneuert(berechtigung=berechtigung(max_token_tage=None)), pubkey_ersatz=RING))

namen.append(efall(
    "kette-laufzeit-zu-lang",
    "Erneuertes Token 60 Tage lang, erlaubt sind 31",
    "DER KERN DER SCHICHT C: ein kompromittierter Lizenzdienst kann höchstens "
    "kurze Tokens ausstellen. Gegenstück: kette-gueltig (30 Tage).",
    ue(u(False, "laufzeit_ueberschritten")),
    token=erneuert(expires_at=iso(JETZT + timedelta(days=57))), pubkey_ersatz=RING))

namen.append(efall(
    "kette-ohne-ablauf",
    "Erneuertes Token mit `expires_at: null`",
    "Unbefristet ist für den Hauptschlüssel erlaubt (Altbestand), für den "
    "Erneuerungsschlüssel nie.",
    ue(u(False, "laufzeit_ueberschritten")),
    token=erneuert(expires_at=None), pubkey_ersatz=RING))

namen.append(efall(
    "kette-nach-der-berechtigung",
    "Berechtigung vor 10 Tagen abgelaufen, Token vor 3 Tagen ausgestellt",
    "Nach Ablauf der Berechtigung stellt der Dienst nichts Gültiges mehr aus.",
    ue(u(False, "berechtigung_abgelaufen")),
    token=erneuert(berechtigung=berechtigung(
        issued_at=iso(JETZT - timedelta(days=300)),
        expires_at=iso(JETZT - timedelta(days=10)))), pubkey_ersatz=RING))

namen.append(efall(
    "kette-letztes-token-der-berechtigung",
    "Berechtigung vor 5 Tagen abgelaufen, Token davor (vor 6 Tagen) ausgestellt",
    "Gemessen wird `issued_at` gegen das Fenster, nicht die Uhr: ein schon "
    "ausgestelltes Token läuft seine kurze Zeit zu Ende, statt dass alle Kunden "
    "im Augenblick des Ablaufs stehen. Gegenstück: kette-nach-der-berechtigung.",
    ue(u(True, "ok")),
    token=erneuert(issued_at=iso(JETZT - timedelta(days=6)),
                   expires_at=iso(JETZT + timedelta(days=24)),
                   berechtigung=berechtigung(
                       issued_at=iso(JETZT - timedelta(days=300)),
                       expires_at=iso(JETZT - timedelta(days=5)))), pubkey_ersatz=RING))

namen.append(efall(
    "als-token-manifest",
    "Ein gültig signiertes Manifest als Token vorgelegt",
    "LÜCKE DER 0.1 (gefunden 29.10.): das Manifest holt jede Installation, es "
    "trägt `product` und kein `expires_at` — als Token war es eine unbefristete "
    "Lizenz ohne Heartbeat. Gilt auch ohne Ring.",
    ue(u(False, "ungueltig")), token=manifest()))

namen.append(efall(
    "als-token-berechtigung",
    "Die Berechtigung selbst als Token vorgelegt",
    "Die Berechtigung ist öffentlich (sie steckt in jedem erneuerten Token) und "
    "vom Hauptschlüssel signiert. Als Token wäre sie eine Lizenz für ein Jahr.",
    ue(u(False, "ungueltig")), token=berechtigung(), pubkey_ersatz=RING))

namen.append(efall(
    "ring-manifest-naechster",
    "Manifest mit `kid: k2`, vom nächsten Schlüssel signiert, Ring",
    "Auch das Manifest rotiert — sonst stünde nach dem Wechsel jeder Widerruf "
    "still (signatur_falsch = unbekannt = Karenz).",
    ue(u(True, "ok", "aktiv", "ok", None,
         zustand(letzter_status="aktiv", letzte_ok_pruefung=iso(JETZT), manifest_seq=10))),
    token=token(), manifest=manifest(NAECHST, kid="k2"), zustand=None, pubkey_ersatz=RING))

namen.append(efall(
    "ring-manifest-kid-unbekannt",
    "Manifest mit `kid: k9`, Ring",
    "Unbekannt wie jede Störung — die Karenz greift, gesperrt wird nicht.",
    ue(u(True, "ok", "unbekannt", "schluessel_unbekannt", None,
         zustand(letzter_status="unbekannt", pending_seit=iso(JETZT)))),
    token=token(), manifest=manifest(kid="k9"), zustand=None, pubkey_ersatz=RING))

print(f"{len(namen)} Fälle geschrieben nach {ZIEL}")
for n in sorted(namen):
    print("  ", n)
