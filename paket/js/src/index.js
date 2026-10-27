// jarvis-lizenz — der geteilte Kern der Lizenzprüfung (JS-Bauart).
//
// COMMONJS, NICHT ESM — und das ist eine Messung, keine Vorliebe. Die Finance
// Suite ist ein CommonJS-Projekt und kann ein ESM-Paket nicht `require()`n;
// umgekehrt liest Node-ESM ein CommonJS-Modul mit einem einfachen
// `module.exports = { … }` problemlos, und Bundler (Next) ebenfalls. Eine
// Bauart bedient damit beide Seiten, ohne dass zwei Fassungen gepflegt werden
// müssen — und zwei Fassungen wären genau die Drift, gegen die es dieses Paket
// gibt.
//
// Reine Zustandsmaschine: KEINE Netzaufrufe, KEINE Datenbank, KEINE Uhr. Alles
// Veränderliche kommt als Argument herein. Genau das macht sie gegen dieselben
// Fälle messbar wie die Python- und die Go-Bauart.
//
// Was der Kern entscheidet, steht in VERTRAG.md; was er ausdrücklich NICHT
// entscheidet (403 gegen Nur-Lese gegen Weiterleitung, welche Pfade frei
// bleiben, ob GET durchgeht) ebenfalls.
//
// Wortgleich zur Python-Bauart — Abweichungen im Verhalten fängt
// pruefstand/laeufer.sh.

const { createPublicKey, verify: edVerify } = require('node:crypto');

class LizenzFehler extends Error {}

function b64urlDec(s) {
  return Buffer.from(s + '='.repeat((4 - (s.length % 4)) % 4), 'base64url');
}

/**
 * ISO-8601 mit oder ohne `Z`. Unlesbar → null, nie eine Ausnahme.
 *
 * NIE gegen die Epoche rechnen: ein unlesbarer Zeitstempel als 0 zu lesen ergibt
 * „vor 496573 Stunden" und damit einen roten Fehlalarm. Diese Falle ist im
 * Maschinenraum zweimal aufgetreten; hier ist sie durch `null` abgeschnitten —
 * der Aufrufer muss den Fall benennen.
 */
function zeitLesen(wert) {
  if (typeof wert !== 'string' || !wert.trim()) return null;
  const t = Date.parse(wert.trim());
  return Number.isNaN(t) ? null : new Date(t);
}

/**
 * `b64url(nutzlast).b64url(signatur)` → Nutzlast, oder LizenzFehler.
 *
 * Verifiziert wird über die DEKODIERTEN Bytes, nicht über eine
 * Neuserialisierung — sonst könnten Unterschiede in Leerzeichen oder
 * Schlüsselreihenfolge eine gültige Signatur brechen.
 */
function pruefeSignatur(draht, pubkeyPem) {
  const teile = String(draht ?? '').trim().split('.');
  if (teile.length !== 2 || !teile[0] || !teile[1]) {
    throw new LizenzFehler('Format ist nicht nutzlast.signatur');
  }
  let roh, sig;
  try {
    roh = b64urlDec(teile[0]);
    sig = b64urlDec(teile[1]);
  } catch (e) {
    throw new LizenzFehler(`base64url unlesbar: ${e.message}`);
  }
  let key;
  try {
    key = createPublicKey(pubkeyPem);
  } catch (e) {
    throw new LizenzFehler(`kein lesbarer Schlüssel: ${e.message}`);
  }
  if (!edVerify(null, roh, key, sig)) throw new LizenzFehler('Signatur passt nicht');

  let nutzlast;
  try {
    nutzlast = JSON.parse(roh.toString('utf-8'));
  } catch (e) {
    throw new LizenzFehler(`Nutzlast ist kein JSON: ${e.message}`);
  }
  if (nutzlast === null || typeof nutzlast !== 'object' || Array.isArray(nutzlast)) {
    throw new LizenzFehler('Nutzlast ist kein Objekt');
  }
  return nutzlast;
}

// ── 1. Das Token ────────────────────────────────────────────────────────────

/**
 * Offline-Gültigkeit: Signatur, Produkt, Ablauf. Sonst nichts.
 * Grenzen (`max_*`) bleiben beim Produkt — sie heißen dort verschieden.
 *
 * Seit 0.2.0 dazu: `offline` (ausdrücklich ausgestellte Offline-Lizenz) und
 * `anker` (`issued_at`), ab dem `sperrgrund` im Kunden-Modus zählt, wenn kein
 * Zustand da ist. Ein Offline-Token OHNE lesbaren Ablauf wird abgewiesen
 * (`offline_ohne_ablauf`): ohne Heartbeat und ohne Ablauf schützte nur noch der
 * Vertrag — genau das „Offline-Perpetual", das es nicht geben soll.
 *
 * @returns {{gueltig: boolean, grund: string, nutzlast: object,
 *            lizenzId: string|null, brauchtHeartbeat: boolean,
 *            offline: boolean, anker: Date|null}}
 */
function pruefeToken(token, pubkeyPem, produkt, jetzt) {
  const fertig = (gueltig, grund, nutzlast = {}) => ({
    gueltig, grund, nutzlast,
    lizenzId: nutzlast.license_id == null ? null : String(nutzlast.license_id),
    brauchtHeartbeat: Boolean(nutzlast.require_heartbeat),
    offline: nutzlast.offline === true,
    anker: zeitLesen(nutzlast.issued_at),
  });

  if (!String(token ?? '').trim()) return fertig(false, 'fehlt');
  let nutzlast;
  try {
    nutzlast = pruefeSignatur(token, pubkeyPem);
  } catch {
    return fertig(false, 'ungueltig');
  }

  // `null`/fehlend wird geduldet: Tokens aus der Zeit vor der Console trugen das
  // Feld nicht. Ein FALSCHES Produkt wird abgewiesen — darum geht es.
  const p = nutzlast.product;
  if (p != null && p !== produkt) return fertig(false, 'falsches_produkt', nutzlast);

  const ablauf = zeitLesen(nutzlast.expires_at);
  if (nutzlast.offline === true && ablauf === null) {
    return fertig(false, 'offline_ohne_ablauf', nutzlast);
  }
  if (ablauf !== null && jetzt > ablauf) return fertig(false, 'abgelaufen', nutzlast);
  return fertig(true, 'ok', nutzlast);
}

/**
 * Gehört das Token zu DIESER Installation? (seit 0.2.0)
 *
 * `'ungebunden'` — das Token trägt keine `install_id` (Altbestand, oder
 * absichtlich nicht gebunden); was dann gilt, entscheidet das Produkt.
 * `'ok'` — gebunden und gleich. `'fremd'` — gebunden und anders, ODER die
 * Installation kennt ihre eigene Kennung nicht: wer seine Kennung verliert,
 * soll nicht als passend durchgehen.
 */
function pruefeBindung(nutzlast, installId) {
  const soll = (nutzlast ?? {}).install_id;
  if (soll === null || soll === undefined || soll === '') return 'ungebunden';
  if (installId === null || installId === undefined || installId === '') return 'fremd';
  return String(soll) === String(installId) ? 'ok' : 'fremd';
}

/**
 * Die Zeit, mit der gerechnet wird: die Uhr, aber nie vor der Hochwassermarke
 * (seit 0.2.0). Die Marke liefert der Aufrufer (z. B. der späteste
 * Zeitstempel in seiner Datenbank) — der Kern bleibt ohne Uhr und ohne DB.
 *
 * Eine zurückgestellte Uhr verlängert so weder Ablauf noch Karenz. Sie wird
 * GEMELDET (`zurueckgestellt`), nicht bestraft: Sperren bleibt Sache des
 * Produkts, und eine Uhr kann auch aus harmlosen Gründen springen.
 *
 * @returns {{jetzt: Date, zurueckgestellt: boolean}}
 */
function wirksameZeit(uhr, marke) {
  if (marke === null || marke === undefined || uhr >= marke) {
    return { jetzt: uhr, zurueckgestellt: false };
  }
  return { jetzt: marke, zurueckgestellt: true };
}

// ── 2. Das Manifest ─────────────────────────────────────────────────────────

/**
 * Das signierte Manifest bewerten. Wirft nie.
 *
 * JEDE Störung ist `unbekannt` — damit greift die Karenzzeit, statt sofort zu
 * sperren. `widerrufen` gibt es nur bei einem ausdrücklichen Eintrag.
 *
 * @returns {{status: string, detail: string, seq: number|null, entitlements: object|null}}
 */
function bewerteManifest(roh, pubkeyPem, lizenzId, jetzt, letzteSeq) {
  const u = (status, detail, seq = null, entitlements = null) =>
    ({ status, detail, seq, entitlements });

  // Nicht erreichbar (Netz, DNS, Zeitüberschreitung). Der Aufrufer holt das
  // Manifest; dass er dabei scheitern kann, ist keine Aussage über die Lizenz.
  if (roh === null || roh === undefined) return u('unbekannt', 'unerreichbar');

  let m;
  try {
    m = pruefeSignatur(roh, pubkeyPem);
  } catch {
    return u('unbekannt', 'signatur_falsch');
  }
  if (m.type !== 'license-manifest') return u('unbekannt', 'kein_manifest');

  // Frischegrenze, kein Ablaufdatum: einem alten Stand wird nicht vertraut,
  // sonst könnte ein Kunde ihn einfrieren, um einem Widerruf zu entgehen.
  const gueltigBis = zeitLesen(m.valid_until);
  if (gueltigBis !== null && jetzt > gueltigBis) return u('unbekannt', 'veraltet');

  const seq = Number.isInteger(m.seq) ? m.seq : null;
  if (seq !== null && letzteSeq != null && seq < letzteSeq) {
    return u('unbekannt', 'rueckrollung');
  }
  if (lizenzId === null || lizenzId === undefined) {
    return u('unbekannt', 'keine_lizenz_id', seq);
  }
  if ((m.revoked ?? []).includes(lizenzId)) return u('widerrufen', 'widerrufen', seq);

  const bekannt = m.licenses ?? {};
  if (!Object.prototype.hasOwnProperty.call(bekannt, lizenzId)) {
    // HÄRTUNG 3: Abwesenheit ist NICHT maßgeblich. Ein gültig signiertes, aber
    // unvollständiges Manifest darf keinen zahlenden Kunden lahmlegen.
    return u('unbekannt', 'nicht_aufgefuehrt', seq);
  }
  const e = bekannt[lizenzId];
  return u('aktiv', 'ok', seq, (e && typeof e === 'object') ? e : {});
}

// ── 3. Der Zustand ──────────────────────────────────────────────────────────

/**
 * Den neuen Zustand rechnen. Rein — der alte bleibt unberührt.
 *
 * Hier stecken zwei der drei Härtungen, und beide sind Einbahnstraßen:
 *
 * HÄRTUNG 2 — `widerrufen` KLEBT. Ein `unbekannt` (Netz gekappt, Signatur
 * kaputt) darf einen bestätigten Widerruf nicht löschen, sonst „ent-widerruft"
 * das Ziehen des Netzsteckers die Lizenz für die ganze Karenzzeit. Nur ein
 * frisches `aktiv` löscht ihn.
 *
 * HÄRTUNG 1 — `pendingSeit` ist der STABILE Anker. Beim ersten Misserfolg
 * gesetzt, danach unangetastet. Würde stattdessen „zuletzt versucht" gezählt,
 * schöbe jeder Fehlversuch die Frist vor sich her und sie liefe nie ab.
 *
 * Dazu: `manifestSeq` und `letzteOkPruefung` steigen nur.
 */
function naechsterZustand(alt, urteil, jetzt) {
  const a = alt ?? {};
  const neu = {
    letzterStatus: urteil.status,
    letzteOkPruefung: a.letzteOkPruefung ?? null,
    pendingSeit: a.pendingSeit ?? null,
    manifestSeq: a.manifestSeq ?? null,
    entitlements: a.entitlements ?? null,
  };
  if (a.letzterStatus === 'widerrufen' && urteil.status === 'unbekannt') {
    neu.letzterStatus = 'widerrufen';
  }
  if (urteil.seq !== null && (neu.manifestSeq === null || urteil.seq > neu.manifestSeq)) {
    neu.manifestSeq = urteil.seq;
  }
  if (urteil.status === 'aktiv') {
    neu.letzteOkPruefung = jetzt;
    neu.pendingSeit = null;
    if (urteil.entitlements !== null) neu.entitlements = urteil.entitlements;
  } else if (neu.pendingSeit === null) {
    neu.pendingSeit = jetzt;
  }
  return neu;
}

/**
 * `null` · `'widerrufen'` · `'pruefung_ueberfaellig'`.
 *
 * KUNDEN-MODUS (seit 0.2.0, `optionen.kundenModus`): die zweite Nachsicht
 * fällt. Fehlt der Zustand — oder trägt er keinen der beiden Anker —, zählt
 * die Karenz ab `optionen.anker` (das `issued_at` des Tokens, siehe
 * `pruefeToken`). Sonst schaltete ein gelöschter Zustand den Fern-Widerruf
 * dauerhaft ab. Ohne lesbaren Anker sperrt der Kunden-Modus sofort. Ohne
 * `optionen` verhält sich alles wie in 0.1.
 *
 * ZWEI NACHSICHTEN, beide gewollt:
 *
 *  • Ohne `require_heartbeat` im signierten Token gibt es nichts zu prüfen — und
 *    damit auch keinen Fern-Widerruf. Das ist die Falle, an der eine
 *    Kundenlizenz fünf Wochen lang scharf AUSSAH und wirkungslos war: Gate an,
 *    Manifest frisch, Widerruf ohne Wirkung.
 *  • Ein gerade gestarteter Dienst (noch kein Zustand) wird nicht gesperrt.
 *    Sonst sperrte jeder Neustart, bis der erste Lauf durch ist.
 */
function sperrgrund(zustand, jetzt, karenzTage, brauchtHeartbeat, optionen = {}) {
  if (!brauchtHeartbeat) return null;
  const karenzMs = Math.max(0, karenzTage) * 86400000;
  const ohneAnker = zustand === null || zustand === undefined
    || (zustand.letzteOkPruefung == null && zustand.pendingSeit == null);
  if (optionen.kundenModus && ohneAnker && zustand?.letzterStatus !== 'widerrufen') {
    const anker = optionen.anker ?? null;
    if (anker === null) return 'pruefung_ueberfaellig';
    return (jetzt - anker) > karenzMs ? 'pruefung_ueberfaellig' : null;
  }
  if (zustand === null || zustand === undefined) return null;
  if (zustand.letzterStatus === 'widerrufen') return 'widerrufen';

  if (zustand.letzteOkPruefung != null) {
    return (jetzt - zustand.letzteOkPruefung) > karenzMs ? 'pruefung_ueberfaellig' : null;
  }
  if (zustand.pendingSeit != null && (jetzt - zustand.pendingSeit) > karenzMs) {
    return 'pruefung_ueberfaellig';
  }
  return null;
}

module.exports = {
  LizenzFehler, zeitLesen, pruefeToken, pruefeBindung, wirksameZeit,
  bewerteManifest, naechsterZustand, sperrgrund,
};
