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
/** Die Nutzlast nennt ein `kid`, das im Schlüsselring nicht steht (seit 0.2.0). */
class SchluesselUnbekannt extends LizenzFehler {}
/** Erneuerungskette richtig signiert, aber außerhalb ihrer Berechtigung. */
class KettenFehler extends LizenzFehler {
  constructor(grund) { super(grund); this.grund = grund; }
}

// Seit 0.2.0. Eine Berechtigung für den Erneuerungsschlüssel gilt höchstens so
// lange — 366 statt 365, damit ein Jahr mit Schalttag hineinpasst.
const BERECHTIGUNG_MAX_TAGE = 366;
const TAG_MS = 86400000;

// Signierte Objekte, die KEIN Token sind. Beide sind öffentlich (das Manifest
// holt jede Installation, die Berechtigung steckt in jedem erneuerten Token),
// beide tragen `product` und kein `expires_at` bzw. ein langes — als Token
// vorgelegt wären sie eine unbefristete Lizenz ohne Heartbeat gewesen.
const KEIN_TOKEN = ['license-manifest', 'erneuerungs-berechtigung'];

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

function teile(draht) {
  const t = String(draht ?? '').trim().split('.');
  if (t.length !== 2 || !t[0] || !t[1]) {
    throw new LizenzFehler('Format ist nicht nutzlast.signatur');
  }
  try {
    return [b64urlDec(t[0]), b64urlDec(t[1])];
  } catch (e) {
    throw new LizenzFehler(`base64url unlesbar: ${e.message}`);
  }
}

function jsonObjekt(roh) {
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

const istRing = (s) => s !== null && typeof s === 'object' && !Array.isArray(s);

/**
 * `b64url(nutzlast).b64url(signatur)` → Nutzlast, oder LizenzFehler.
 *
 * Verifiziert wird über die DEKODIERTEN Bytes, nicht über eine
 * Neuserialisierung — sonst könnten Unterschiede in Leerzeichen oder
 * Schlüsselreihenfolge eine gültige Signatur brechen.
 *
 * `schluessel` ist ein PEM (wie in 0.1 — ein `kid` in der Nutzlast wird dann
 * nicht gelesen) oder seit 0.2.0 ein SCHLÜSSELRING `{kid: PEM}`. Mit Ring
 * entscheidet das `kid` der Nutzlast, welcher Schlüssel prüft; ein `kid`, das
 * nicht im Ring steht, ist `SchluesselUnbekannt`. Ohne `kid` (Altbestand) darf
 * jeder Schlüssel des Rings passen.
 */
function pruefeSignatur(draht, schluessel, v) {
  const [roh, sig] = teile(draht);
  if (!istRing(schluessel)) {
    verifiziere(roh, sig, schluessel, v);
    return jsonObjekt(roh);
  }
  const nutzlast = jsonObjekt(roh);
  const kid = nutzlast.kid;
  if (kid === null || kid === undefined) {
    for (const pem of Object.values(schluessel)) {
      try {
        verifiziere(roh, sig, pem, v);
        return nutzlast;
      } catch { /* nächster Schlüssel */ }
    }
    throw new LizenzFehler('kein Schlüssel des Rings passt');
  }
  if (typeof kid !== 'string' || !Object.prototype.hasOwnProperty.call(schluessel, kid)) {
    throw new SchluesselUnbekannt(`kid ${JSON.stringify(kid)} steht nicht im Ring`);
  }
  verifiziere(roh, sig, schluessel[kid], v);
  return nutzlast;
}

// Seit 0.2.1. DER-Kopf eines Ed25519-SPKI: SEQUENCE(42) { SEQUENCE(5) { OID
// 1.3.101.112 }, BIT STRING(33, 0 ungenutzte Bits) } — danach die 32 Rohbytes.
const ED25519_SPKI_PRAEFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * SPKI-PEM → die 32 Rohbytes des Ed25519-Schlüssels, oder LizenzFehler (seit 0.2.1).
 *
 * Absichtlich OHNE `createPublicKey`: diese Zerlegung ist der Weg der
 * eingespeisten Prüfung, und die soll node:crypto gar nicht berühren — ein
 * vorgeladenes Paket, das `createPublicKey` umbiegt, könnte sonst für den
 * Prüfschlüssel des Images den Schlüssel des Angreifers zurückgeben.
 */
function rohSchluessel(pem) {
  if (typeof pem !== 'string') throw new LizenzFehler('Schlüssel ist kein PEM');
  const zeilen = pem.trim().split(/\r?\n/).map((z) => z.trim());
  if (zeilen.length < 3 || zeilen[0] !== '-----BEGIN PUBLIC KEY-----'
      || zeilen[zeilen.length - 1] !== '-----END PUBLIC KEY-----') {
    throw new LizenzFehler('Schlüssel ist kein SPKI-PEM');
  }
  const b64 = zeilen.slice(1, -1).join('');
  // Buffer.from(…, 'base64') überspringt fremde Zeichen stillschweigend — darum vorher streng.
  if (b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new LizenzFehler('PEM-Inhalt ist kein base64');
  }
  const der = Buffer.from(b64, 'base64');
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PRAEFIX)) {
    throw new LizenzFehler('kein Ed25519-SPKI-Schlüssel');
  }
  return new Uint8Array(der.subarray(12));
}

// `v` ist die eingespeiste Prüfung (seit 0.2.1) oder `undefined`. Mit ihr
// entscheidet NUR sie, und nur ein echtes `true` zählt — `1`, `'true'`, ein
// Wurf: alles „Signatur passt nicht".
function verifiziere(roh, sig, pubkeyPem, v) {
  if (v !== undefined) {
    const schluessel = rohSchluessel(pubkeyPem);
    let ja;
    try {
      ja = v(roh, sig, schluessel);
    } catch {
      ja = false;
    }
    if (ja !== true) throw new LizenzFehler('Signatur passt nicht');
    return;
  }
  let key;
  try {
    key = createPublicKey(pubkeyPem);
  } catch (e) {
    throw new LizenzFehler(`kein lesbarer Schlüssel: ${e.message}`);
  }
  if (!edVerify(null, roh, key, sig)) throw new LizenzFehler('Signatur passt nicht');
}

// `null`/fehlend heißt: keine eingespeiste Prüfung. Alles andere wird benutzt —
// auch eine Nicht-Funktion; deren Aufruf wirft, und das ist „falsch", nie „egal".
const eingespeist = (optionen) => optionen?.verifiziere ?? undefined;

// Wie `_ganz_positiv` in Python und die float64-Prüfung in Go: 31.0 zählt.
const ganzPositiv = (x) => typeof x === 'number' && Number.isInteger(x) && x > 0;

/**
 * Die Erneuerungskette (seit 0.2.0) → Nutzlast, oder `null` ohne Kette.
 *
 * Ein Token mit `berechtigung` ist NICHT vom Hauptschlüssel signiert, sondern
 * vom Erneuerungsschlüssel des Lizenzdienstes. Die Berechtigung ist ein vom
 * Hauptschlüssel signiertes Objekt, das den Erneuerungsschlüssel nennt und
 * begrenzt: höchstens `BERECHTIGUNG_MAX_TAGE` gültig, Tokens höchstens
 * `max_token_tage` lang, nur für `product`. Ein kompromittierter Dienst kann so
 * höchstens kurze Tokens ausstellen — nie ein unbefristetes.
 *
 * Die Reihenfolge der Prüfungen ist Teil des Vertrags (alle drei Bauarten
 * gleich): Signaturen → Produkt → Berechtigung → Laufzeit → Zeitfenster.
 * Gemessen wird `issued_at` des Tokens gegen das Fenster der Berechtigung,
 * nicht die Uhr: läuft die Berechtigung ab, bleiben schon ausgestellte Tokens
 * ihre kurze Laufzeit gültig, statt alle Kunden im selben Augenblick zu sperren.
 */
function kette(token, schluessel, produkt, v) {
  const [roh, sig] = teile(token);
  let vorab;
  try {
    vorab = jsonObjekt(roh);
  } catch {
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(vorab, 'berechtigung')) return null;
  const bDraht = vorab.berechtigung;
  if (typeof bDraht !== 'string') throw new LizenzFehler('berechtigung ist keine Zeichenkette');
  const b = pruefeSignatur(bDraht, schluessel, v);
  if (b.type !== 'erneuerungs-berechtigung') throw new LizenzFehler('berechtigung hat den falschen Typ');
  if (typeof b.pubkey !== 'string') throw new LizenzFehler('berechtigung nennt keinen Schlüssel');
  verifiziere(roh, sig, b.pubkey, v);

  if (b.product !== produkt) throw new KettenFehler('falsches_produkt');
  const bVon = zeitLesen(b.issued_at);
  const bBis = zeitLesen(b.expires_at);
  const maxTage = b.max_token_tage;
  if (bVon === null || bBis === null || bBis < bVon
      || bBis - bVon > BERECHTIGUNG_MAX_TAGE * TAG_MS || !ganzPositiv(maxTage)) {
    throw new KettenFehler('berechtigung_ungueltig');
  }
  const tVon = zeitLesen(vorab.issued_at);
  const tBis = zeitLesen(vorab.expires_at);
  if (tVon === null || tBis === null || tBis < tVon || tBis - tVon > maxTage * TAG_MS) {
    throw new KettenFehler('laufzeit_ueberschritten');
  }
  if (tVon < bVon || tVon > bBis) throw new KettenFehler('berechtigung_abgelaufen');
  return vorab;
}

// ── 1. Das Token ────────────────────────────────────────────────────────────

/**
 * Offline-Gültigkeit: Signatur, Produkt, Ablauf. Sonst nichts.
 * Grenzen (`max_*`) bleiben beim Produkt — sie heißen dort verschieden.
 *
 * Seit 0.2.0 darf `pubkeyPem` ein Schlüsselring `{kid: PEM}` sein, und ein
 * Token darf über eine Erneuerungskette signiert sein (siehe `kette`).
 *
 * Seit 0.2.0 dazu: `offline` (ausdrücklich ausgestellte Offline-Lizenz) und
 * `anker` (`issued_at`), ab dem `sperrgrund` im Kunden-Modus zählt, wenn kein
 * Zustand da ist. Ein Offline-Token OHNE lesbaren Ablauf wird abgewiesen
 * (`offline_ohne_ablauf`): ohne Heartbeat und ohne Ablauf schützte nur noch der
 * Vertrag — genau das „Offline-Perpetual", das es nicht geben soll.
 *
 * Seit 0.2.1: `optionen.verifiziere(roh, sig, rohSchluessel) → boolean` ist
 * eine EINGESPEISTE Ed25519-Prüfung. Mit ihr prüft der Kern jede Signatur
 * (Schlüssel, Ring, Kette) nur über sie und berührt node:crypto dafür nicht —
 * ein vorgeladenes Paket im Kunden-Image kann `crypto.verify` umbiegen, eine
 * ins Erzeugnis gebündelte Prüfung nicht. Ohne Option alles wie in 0.2.0.
 *
 * @returns {{gueltig: boolean, grund: string, nutzlast: object,
 *            lizenzId: string|null, brauchtHeartbeat: boolean,
 *            offline: boolean, anker: Date|null}}
 */
function pruefeToken(token, pubkeyPem, produkt, jetzt, optionen = {}) {
  const v = eingespeist(optionen);
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
    nutzlast = kette(token, pubkeyPem, produkt, v);
    if (nutzlast === null) {
      nutzlast = pruefeSignatur(token, pubkeyPem, v);
      if (KEIN_TOKEN.includes(nutzlast.type)) return fertig(false, 'ungueltig');
    }
  } catch (e) {
    if (e instanceof SchluesselUnbekannt) return fertig(false, 'schluessel_unbekannt');
    if (e instanceof KettenFehler) return fertig(false, e.grund);
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
  // Nur eine Zeichenkette bindet. Eine Zahl oder Liste schriebe jede Sprache
  // anders als Text, und die Bauarten kämen zu verschiedenen Urteilen.
  if (typeof soll !== 'string') return 'fremd';
  if (typeof installId !== 'string' || installId === '') return 'fremd';
  return soll === installId ? 'ok' : 'fremd';
}

// Ein `Date`, das auch eines ist. `new Date(undefined)` ist ein Date-Objekt mit
// NaN — jeder Vergleich damit ist falsch, und ein falscher Vergleich hiesse
// hier „nicht abgelaufen", „nicht überfällig". Alles andere zählt als fehlend.
function gueltigeZeit(x) {
  return x instanceof Date && !Number.isNaN(x.getTime()) ? x : null;
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
  marke = gueltigeZeit(marke);
  if (marke === null || uhr >= marke) {
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
 * `optionen.verifiziere` wie bei `pruefeToken` (seit 0.2.1).
 *
 * @returns {{status: string, detail: string, seq: number|null, entitlements: object|null}}
 */
function bewerteManifest(roh, pubkeyPem, lizenzId, jetzt, letzteSeq, optionen = {}) {
  const v = eingespeist(optionen);
  const u = (status, detail, seq = null, entitlements = null) =>
    ({ status, detail, seq, entitlements });

  // Nicht erreichbar (Netz, DNS, Zeitüberschreitung). Der Aufrufer holt das
  // Manifest; dass er dabei scheitern kann, ist keine Aussage über die Lizenz.
  if (roh === null || roh === undefined) return u('unbekannt', 'unerreichbar');

  let m;
  try {
    m = pruefeSignatur(roh, pubkeyPem, v);
  } catch (e) {
    return u('unbekannt', e instanceof SchluesselUnbekannt ? 'schluessel_unbekannt' : 'signatur_falsch');
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
 * fällt. Solange es keinen erfolgreichen Lauf gibt, zählt die Karenz ab dem
 * FRÜHEREN von `pendingSeit` und `optionen.anker` (das `issued_at` des Tokens,
 * siehe `pruefeToken`). Nur ab `pendingSeit` zu zählen reichte nicht: ein
 * gelöschter Zustand plus ein gesperrter Lizenzserver setzte `pendingSeit`
 * im nächsten Lauf auf „jetzt" und schenkte eine frische Karenz, beliebig oft.
 * Ohne lesbaren Anker sperrt der Kunden-Modus sofort; eine `letzteOkPruefung`
 * in der Zukunft gilt als fehlend. Ohne `optionen` verhält sich alles wie in 0.1.
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
  if (optionen.kundenModus) {
    if (zustand?.letzterStatus === 'widerrufen') return 'widerrufen';
    const ok = gueltigeZeit(zustand?.letzteOkPruefung ?? null);
    if (ok !== null && ok <= jetzt) {
      return (jetzt - ok) > karenzMs ? 'pruefung_ueberfaellig' : null;
    }
    const anker = gueltigeZeit(optionen.anker ?? null);
    if (anker === null) return 'pruefung_ueberfaellig';
    const offen = gueltigeZeit(zustand?.pendingSeit ?? null);
    const start = offen !== null && offen < anker ? offen : anker;
    return (jetzt - start) > karenzMs ? 'pruefung_ueberfaellig' : null;
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
  LizenzFehler, SchluesselUnbekannt, BERECHTIGUNG_MAX_TAGE, zeitLesen, pruefeToken, pruefeBindung, wirksameZeit,
  bewerteManifest, naechsterZustand, sperrgrund, rohSchluessel,
};
