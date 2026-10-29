"""jarvis-lizenz — der geteilte Kern der Lizenzprüfung.

Reine Zustandsmaschine: **keine** Netzaufrufe, **keine** Datenbank, **keine**
Uhr. Alles Veränderliche kommt als Argument herein. Genau das macht ihn in drei
Sprachen gegen dieselben Fälle messbar — und es ist der Grund, warum die Fälle
sprachneutrales JSON sein können.

Was der Kern entscheidet, steht in VERTRAG.md; was er ausdrücklich NICHT
entscheidet (403 gegen Nur-Lese gegen Weiterleitung, welche Pfade frei bleiben,
ob GET durchgeht) ebenfalls.

Abgeleitet aus `jarvis-email-dashboard/dashboard/license_heartbeat.py` — der
Fassung, in der die drei Härtungen nachweislich stehen.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "LizenzFehler", "TokenUrteil", "ManifestUrteil", "Zustand",
    "pruefe_token", "bewerte_manifest", "naechster_zustand", "sperrgrund",
    "zeit_lesen", "pruefe_bindung", "wirksame_zeit",
    "SchluesselUnbekannt", "BERECHTIGUNG_MAX_TAGE",
]

# ── Draht ────────────────────────────────────────────────────────────────────


class LizenzFehler(ValueError):
    """Token oder Manifest ist unlesbar oder falsch signiert."""


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def zeit_lesen(wert: Any) -> datetime | None:
    """ISO-8601 mit oder ohne `Z`. Unlesbar → None, nie eine Ausnahme.

    NIE gegen die Epoche rechnen: ein unlesbarer Zeitstempel als 0 zu lesen
    ergibt „vor 496573 Stunden" und damit einen roten Fehlalarm. Diese Falle ist
    im Maschinenraum zweimal aufgetreten; hier ist sie durch `None` abgeschnitten
    — der Aufrufer muss den Fall benennen.
    """
    if not isinstance(wert, str) or not wert.strip():
        return None
    try:
        d = datetime.fromisoformat(wert.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class SchluesselUnbekannt(LizenzFehler):
    """Die Nutzlast nennt ein `kid`, das im Schlüsselring nicht steht (seit 0.2.0)."""


class _KettenFehler(LizenzFehler):
    """Erneuerungskette richtig signiert, aber ausserhalb ihrer Berechtigung."""

    def __init__(self, grund: str):
        super().__init__(grund)
        self.grund = grund


# Seit 0.2.0. Eine Berechtigung für den Erneuerungsschlüssel gilt höchstens so
# lange — 366 statt 365, damit ein Jahr mit Schalttag hineinpasst.
BERECHTIGUNG_MAX_TAGE = 366

# Signierte Objekte, die KEIN Token sind. Beide sind öffentlich (das Manifest
# holt jede Installation, die Berechtigung steckt in jedem erneuerten Token),
# beide tragen `product` und kein `expires_at` bzw. ein langes — als Token
# vorgelegt wären sie eine unbefristete Lizenz ohne Heartbeat gewesen.
_KEIN_TOKEN = ("license-manifest", "erneuerungs-berechtigung")


def _teile(draht: str) -> tuple[bytes, bytes]:
    teile = (draht or "").strip().split(".")
    if len(teile) != 2 or not teile[0] or not teile[1]:
        raise LizenzFehler("Format ist nicht nutzlast.signatur")
    try:
        return _b64url_dec(teile[0]), _b64url_dec(teile[1])
    except Exception as e:
        raise LizenzFehler(f"base64url unlesbar: {e}") from e


def _json_objekt(roh: bytes) -> dict:
    try:
        nutzlast = json.loads(roh.decode("utf-8"))
    except Exception as e:
        raise LizenzFehler(f"Nutzlast ist kein JSON: {e}") from e
    if not isinstance(nutzlast, dict):
        raise LizenzFehler("Nutzlast ist kein Objekt")
    return nutzlast


def _pruefe_signatur(draht: str, schluessel: str | dict) -> dict:
    """`b64url(nutzlast).b64url(signatur)` → Nutzlast, oder LizenzFehler.

    Verifiziert wird über die DEKODIERTEN Bytes, nicht über eine
    Neuserialisierung — sonst könnten Unterschiede in Leerzeichen oder
    Schlüsselreihenfolge eine gültige Signatur brechen.

    `schluessel` ist ein PEM (wie in 0.1 — ein `kid` in der Nutzlast wird dann
    nicht gelesen) oder seit 0.2.0 ein SCHLÜSSELRING `{kid: PEM}`. Mit Ring
    entscheidet das `kid` der Nutzlast, welcher Schlüssel prüft; ein `kid`, das
    nicht im Ring steht, ist `SchluesselUnbekannt`. Ohne `kid` (Altbestand)
    darf jeder Schlüssel des Rings passen.
    """
    roh, sig = _teile(draht)
    if not isinstance(schluessel, dict):
        _verifiziere(roh, sig, schluessel)
        return _json_objekt(roh)
    nutzlast = _json_objekt(roh)
    kid = nutzlast.get("kid")
    if kid is None:
        for pem in schluessel.values():
            try:
                _verifiziere(roh, sig, pem)
                return nutzlast
            except LizenzFehler:
                pass
        raise LizenzFehler("kein Schlüssel des Rings passt")
    if not isinstance(kid, str) or kid not in schluessel:
        raise SchluesselUnbekannt(f"kid {kid!r} steht nicht im Ring")
    _verifiziere(roh, sig, schluessel[kid])
    return nutzlast


def _verifiziere(roh: bytes, sig: bytes, pubkey_pem: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Ein kaputter oder leerer Schluessel ist ein LizenzFehler, kein roher
    # ValueError. Sonst schlaegt er beim Aufrufer als 500 durch statt als
    # "ungueltig" — BauKI hatte diese Haertung als EINZIGES der fuenf Produkte,
    # und die JS- wie die Go-Bauart hier hatten sie von Anfang an. Nur die
    # Python-Bauart nicht, und KEIN Fall hat es gemerkt: es gab keinen mit einem
    # kaputten Schluessel. Genau dafuer ist der Pruefstand da.
    try:
        schluessel = serialization.load_pem_public_key(pubkey_pem.encode())
    except (ValueError, TypeError) as e:
        raise LizenzFehler(f"Schlüssel unlesbar: {e}") from e
    if not isinstance(schluessel, Ed25519PublicKey):
        raise LizenzFehler("kein Ed25519-Schlüssel")
    try:
        schluessel.verify(sig, roh)
    except InvalidSignature as e:
        raise LizenzFehler("Signatur passt nicht") from e


def _ganz_positiv(x: Any) -> bool:
    # Wie `Number.isInteger` in JS und die float64-Prüfung in Go: 31.0 zählt.
    return (isinstance(x, (int, float)) and not isinstance(x, bool)
            and x > 0 and x == int(x))


def _kette(token: str, schluessel: str | dict, produkt: str) -> dict | None:
    """Die Erneuerungskette (seit 0.2.0) → Nutzlast, oder None ohne Kette.

    Ein Token mit `berechtigung` ist NICHT vom Hauptschlüssel signiert, sondern
    vom Erneuerungsschlüssel des Lizenzdienstes. Die Berechtigung ist ein vom
    Hauptschlüssel signiertes Objekt, das den Erneuerungsschlüssel nennt und
    begrenzt: höchstens `BERECHTIGUNG_MAX_TAGE` gültig, Tokens höchstens
    `max_token_tage` lang, nur für `product`. Ein kompromittierter Dienst kann
    so höchstens kurze Tokens ausstellen — nie ein unbefristetes.

    Die Reihenfolge der Prüfungen ist Teil des Vertrags (alle drei Bauarten
    gleich): Signaturen → Produkt → Berechtigung → Laufzeit → Zeitfenster.
    Gemessen wird `issued_at` des Tokens gegen das Fenster der Berechtigung,
    nicht die Uhr: läuft die Berechtigung ab, bleiben schon ausgestellte Tokens
    ihre kurze Laufzeit gültig, statt alle Kunden im selben Augenblick zu sperren.
    """
    roh, sig = _teile(token)
    try:
        vorab = _json_objekt(roh)
    except LizenzFehler:
        return None
    if "berechtigung" not in vorab:
        return None
    b_draht = vorab["berechtigung"]
    if not isinstance(b_draht, str):
        raise LizenzFehler("berechtigung ist keine Zeichenkette")
    b = _pruefe_signatur(b_draht, schluessel)
    if b.get("type") != "erneuerungs-berechtigung":
        raise LizenzFehler("berechtigung hat den falschen Typ")
    if not isinstance(b.get("pubkey"), str):
        raise LizenzFehler("berechtigung nennt keinen Schlüssel")
    _verifiziere(roh, sig, b["pubkey"])

    if b.get("product") != produkt:
        raise _KettenFehler("falsches_produkt")
    b_von, b_bis = zeit_lesen(b.get("issued_at")), zeit_lesen(b.get("expires_at"))
    max_tage = b.get("max_token_tage")
    if (b_von is None or b_bis is None or b_bis < b_von
            or b_bis - b_von > timedelta(days=BERECHTIGUNG_MAX_TAGE)
            or not _ganz_positiv(max_tage)):
        raise _KettenFehler("berechtigung_ungueltig")
    t_von, t_bis = zeit_lesen(vorab.get("issued_at")), zeit_lesen(vorab.get("expires_at"))
    if t_von is None or t_bis is None or t_bis < t_von or t_bis - t_von > timedelta(days=max_tage):
        raise _KettenFehler("laufzeit_ueberschritten")
    if t_von < b_von or t_von > b_bis:
        raise _KettenFehler("berechtigung_abgelaufen")
    return vorab


# ── 1. Das Token ─────────────────────────────────────────────────────────────


@dataclass
class TokenUrteil:
    gueltig: bool
    # ok | fehlt | ungueltig | falsches_produkt | abgelaufen | offline_ohne_ablauf
    # seit 0.2.0 auch: schluessel_unbekannt | berechtigung_ungueltig
    #                  | laufzeit_ueberschritten | berechtigung_abgelaufen
    grund: str
    nutzlast: dict = field(default_factory=dict)

    @property
    def lizenz_id(self) -> str | None:
        w = self.nutzlast.get("license_id")
        return str(w) if w is not None else None

    @property
    def braucht_heartbeat(self) -> bool:
        return bool(self.nutzlast.get("require_heartbeat"))

    @property
    def offline(self) -> bool:
        """Ausdrücklich ausgestellte Offline-Lizenz (seit 0.2.0)."""
        return self.nutzlast.get("offline") is True

    @property
    def anker(self) -> datetime | None:
        """`issued_at` — ab hier zählt der Kunden-Modus ohne Zustand (seit 0.2.0)."""
        return zeit_lesen(self.nutzlast.get("issued_at"))


def pruefe_token(token: str, pubkey_pem: str | dict, produkt: str,
                 jetzt: datetime) -> TokenUrteil:
    """Offline-Gültigkeit: Signatur, Produkt, Ablauf. Sonst nichts.

    Grenzen (`max_*`) bleiben beim Produkt — sie heissen dort verschieden und
    haengen an einer Zahl, die nur das Produkt kennt.

    Seit 0.2.0: `pubkey_pem` darf ein Schlüsselring `{kid: PEM}` sein, und ein
    Token darf über eine Erneuerungskette signiert sein (siehe `_kette`).
    """
    if not (token or "").strip():
        return TokenUrteil(False, "fehlt")
    try:
        nutzlast = _kette(token, pubkey_pem, produkt)
        if nutzlast is None:
            nutzlast = _pruefe_signatur(token, pubkey_pem)
            if nutzlast.get("type") in _KEIN_TOKEN:
                return TokenUrteil(False, "ungueltig")
    except SchluesselUnbekannt:
        return TokenUrteil(False, "schluessel_unbekannt")
    except _KettenFehler as e:
        return TokenUrteil(False, e.grund)
    except LizenzFehler:
        return TokenUrteil(False, "ungueltig")

    # `None` wird geduldet: Tokens aus der Zeit vor der Console trugen das Feld
    # nicht. Ein FALSCHES Produkt wird abgewiesen — darum geht es.
    p = nutzlast.get("product")
    if p is not None and p != produkt:
        return TokenUrteil(False, "falsches_produkt", nutzlast)

    ablauf = zeit_lesen(nutzlast.get("expires_at"))
    # Seit 0.2.0: ohne Heartbeat UND ohne Ablauf schützte nur noch der Vertrag —
    # das „Offline-Perpetual", das es nicht geben soll.
    if nutzlast.get("offline") is True and ablauf is None:
        return TokenUrteil(False, "offline_ohne_ablauf", nutzlast)
    if ablauf is not None and jetzt > ablauf:
        return TokenUrteil(False, "abgelaufen", nutzlast)
    return TokenUrteil(True, "ok", nutzlast)


def pruefe_bindung(nutzlast: dict | None, install_id: Any) -> str:
    """Gehört das Token zu DIESER Installation? (seit 0.2.0)

    `ungebunden` — das Token trägt keine `install_id`; was dann gilt, entscheidet
    das Produkt. `ok` — gebunden und gleich. `fremd` — gebunden und anders,
    ODER die Installation kennt ihre eigene Kennung nicht: wer seine Kennung
    verliert, soll nicht als passend durchgehen.
    """
    soll = (nutzlast or {}).get("install_id")
    if soll is None or soll == "":
        return "ungebunden"
    # Nur eine Zeichenkette bindet — eine Zahl oder Liste schriebe jede Sprache
    # anders als Text, und die Bauarten kämen zu verschiedenen Urteilen.
    if not isinstance(soll, str):
        return "fremd"
    if not isinstance(install_id, str) or install_id == "":
        return "fremd"
    return "ok" if soll == install_id else "fremd"


def wirksame_zeit(uhr: datetime, marke: datetime | None) -> tuple[datetime, bool]:
    """Die Uhr, aber nie vor der Hochwassermarke des Aufrufers (seit 0.2.0).

    Gibt `(jetzt, zurueckgestellt)` zurück. Eine zurückgestellte Uhr verlängert
    so weder Ablauf noch Karenz; sie wird GEMELDET, nicht bestraft — Sperren
    bleibt Sache des Produkts.
    """
    if marke is None or uhr >= marke:
        return uhr, False
    return marke, True


# ── 2. Das Manifest ──────────────────────────────────────────────────────────


@dataclass
class ManifestUrteil:
    # aktiv | widerrufen | unbekannt
    status: str
    detail: str
    seq: int | None = None
    entitlements: dict | None = None


def bewerte_manifest(roh: str | None, pubkey_pem: str | dict, lizenz_id: str | None,
                     jetzt: datetime, letzte_seq: int | None) -> ManifestUrteil:
    """Das signierte Manifest bewerten. Wirft nie.

    JEDE Störung ist `unbekannt` — damit greift die Karenzzeit, statt sofort zu
    sperren. `widerrufen` gibt es nur bei einem ausdrücklichen Eintrag.
    """
    if roh is None:
        # Nicht erreichbar (Netz, DNS, Zeitüberschreitung). Der Aufrufer holt
        # das Manifest; dass er dabei scheitern kann, ist keine Aussage über die
        # Lizenz.
        return ManifestUrteil("unbekannt", "unerreichbar")
    try:
        m = _pruefe_signatur(roh, pubkey_pem)
    except SchluesselUnbekannt:
        return ManifestUrteil("unbekannt", "schluessel_unbekannt")
    except LizenzFehler:
        return ManifestUrteil("unbekannt", "signatur_falsch")

    if m.get("type") != "license-manifest":
        return ManifestUrteil("unbekannt", "kein_manifest")

    # Frischegrenze, kein Ablaufdatum: einem alten Stand wird nicht vertraut,
    # sonst könnte ein Kunde ihn einfrieren, um einem Widerruf zu entgehen.
    gueltig_bis = zeit_lesen(m.get("valid_until"))
    if gueltig_bis is not None and jetzt > gueltig_bis:
        return ManifestUrteil("unbekannt", "veraltet")

    seq = m.get("seq") if isinstance(m.get("seq"), int) else None
    if seq is not None and letzte_seq is not None and seq < letzte_seq:
        return ManifestUrteil("unbekannt", "rueckrollung")

    if lizenz_id is None:
        return ManifestUrteil("unbekannt", "keine_lizenz_id", seq)

    if lizenz_id in set(m.get("revoked") or []):
        return ManifestUrteil("widerrufen", "widerrufen", seq)

    bekannt = m.get("licenses") or {}
    if lizenz_id not in bekannt:
        # HÄRTUNG 3: Abwesenheit ist NICHT maßgeblich. Ein gültig signiertes,
        # aber unvollständiges Manifest darf keinen zahlenden Kunden lahmlegen.
        return ManifestUrteil("unbekannt", "nicht_aufgefuehrt", seq)

    e = bekannt.get(lizenz_id)
    return ManifestUrteil("aktiv", "ok", seq, e if isinstance(e, dict) else {})


# ── 3. Der Zustand ───────────────────────────────────────────────────────────


@dataclass
class Zustand:
    """Was zwischen zwei Läufen überdauert. Der Aufrufer legt ihn ab, wo er will."""
    letzter_status: str | None = None          # aktiv | widerrufen | unbekannt
    letzte_ok_pruefung: datetime | None = None
    pending_seit: datetime | None = None
    manifest_seq: int | None = None
    entitlements: dict | None = None


def naechster_zustand(alt: Zustand, urteil: ManifestUrteil,
                      jetzt: datetime) -> Zustand:
    """Den neuen Zustand rechnen. Rein — der alte bleibt unberührt.

    Hier stecken zwei der drei Härtungen, und beide sind Einbahnstraßen:

    HÄRTUNG 2 — `widerrufen` KLEBT. Ein `unbekannt` (Netz gekappt, Signatur
    kaputt) darf einen bestätigten Widerruf nicht löschen, sonst „ent-widerruft"
    das Ziehen des Netzsteckers die Lizenz für die ganze Karenzzeit. Nur ein
    frisches `aktiv` löscht ihn.

    HÄRTUNG 1 — `pending_seit` ist der STABILE Anker. Beim ersten Misserfolg
    gesetzt, danach unangetastet. Würde stattdessen „zuletzt versucht" gezählt,
    schöbe jeder Fehlversuch die Frist vor sich her und sie liefe nie ab.

    Dazu: `manifest_seq` und `letzte_ok_pruefung` steigen nur — ein Fehlschlag
    darf keinen Hochstand senken.
    """
    neu = Zustand(
        letzter_status=urteil.status,
        letzte_ok_pruefung=alt.letzte_ok_pruefung,
        pending_seit=alt.pending_seit,
        manifest_seq=alt.manifest_seq,
        entitlements=alt.entitlements,
    )
    if alt.letzter_status == "widerrufen" and urteil.status == "unbekannt":
        neu.letzter_status = "widerrufen"

    if urteil.seq is not None and (neu.manifest_seq is None or urteil.seq > neu.manifest_seq):
        neu.manifest_seq = urteil.seq

    if urteil.status == "aktiv":
        neu.letzte_ok_pruefung = jetzt
        neu.pending_seit = None
        if urteil.entitlements is not None:
            neu.entitlements = urteil.entitlements
    else:
        if neu.pending_seit is None:
            neu.pending_seit = jetzt
    return neu


def sperrgrund(zustand: Zustand | None, jetzt: datetime, karenz_tage: int,
               braucht_heartbeat: bool, kunden_modus: bool = False,
               anker: datetime | None = None) -> str | None:
    """`None` · `widerrufen` · `pruefung_ueberfaellig`.

    KUNDEN-MODUS (seit 0.2.0): die zweite Nachsicht fällt. Solange es keinen
    erfolgreichen Lauf gibt, zählt die Karenz ab dem FRÜHEREN von
    `pending_seit` und `anker` (das `issued_at` des Tokens). Nur ab
    `pending_seit` zu zählen reichte nicht: ein gelöschter Zustand plus ein
    gesperrter Lizenzserver setzte `pending_seit` im nächsten Lauf auf „jetzt“
    und schenkte eine frische Karenz, beliebig oft. Ohne lesbaren Anker sperrt
    der Kunden-Modus sofort; eine `letzte_ok_pruefung` in der Zukunft gilt als
    fehlend. Ohne `kunden_modus` verhält sich alles wie in 0.1.

    ZWEI NACHSICHTEN, beide gewollt:

    * Ohne `require_heartbeat` im signierten Token gibt es nichts zu prüfen —
      und damit auch keinen Fern-Widerruf. Das ist die Falle, an der eine
      Kundenlizenz fünf Wochen lang scharf AUSSAH und wirkungslos war: Gate an,
      Manifest frisch, Widerruf ohne Wirkung.
    * Ein gerade gestarteter Dienst (noch kein Zustand) wird nicht gesperrt.
      Sonst sperrte jeder Neustart, bis der erste Lauf durch ist.
    """
    if not braucht_heartbeat:
        return None
    karenz = timedelta(days=max(0, karenz_tage))
    if kunden_modus:
        if zustand is not None and zustand.letzter_status == "widerrufen":
            return "widerrufen"
        ok = zustand.letzte_ok_pruefung if zustand is not None else None
        if ok is not None and ok <= jetzt:
            return "pruefung_ueberfaellig" if (jetzt - ok) > karenz else None
        if anker is None:
            return "pruefung_ueberfaellig"
        offen = zustand.pending_seit if zustand is not None else None
        start = offen if offen is not None and offen < anker else anker
        return "pruefung_ueberfaellig" if (jetzt - start) > karenz else None
    if zustand is None:
        return None
    if zustand.letzter_status == "widerrufen":
        return "widerrufen"

    if zustand.letzte_ok_pruefung is not None:
        return "pruefung_ueberfaellig" if (jetzt - zustand.letzte_ok_pruefung) > karenz else None
    if zustand.pending_seit is not None and (jetzt - zustand.pending_seit) > karenz:
        return "pruefung_ueberfaellig"
    return None
