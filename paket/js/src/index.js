// jarvis-lizenz — der geteilte Kern der Lizenzprüfung (JS-Bauart).
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

import { createPublicKey, verify as edVerify } from 'node:crypto';

export class LizenzFehler extends Error {}

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
export function zeitLesen(wert) {
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
 * @returns {{gueltig: boolean, grund: string, nutzlast: object,
 *            lizenzId: string|null, brauchtHeartbeat: boolean}}
 */
export function pruefeToken(token, pubkeyPem, produkt, jetzt) {
  const fertig = (gueltig, grund, nutzlast = {}) => ({
    gueltig, grund, nutzlast,
    lizenzId: nutzlast.license_id == null ? null : String(nutzlast.license_id),
    brauchtHeartbeat: Boolean(nutzlast.require_heartbeat),
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
  if (ablauf !== null && jetzt > ablauf) return fertig(false, 'abgelaufen', nutzlast);
  return fertig(true, 'ok', nutzlast);
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
export function bewerteManifest(roh, pubkeyPem, lizenzId, jetzt, letzteSeq) {
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
export function naechsterZustand(alt, urteil, jetzt) {
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
 * ZWEI NACHSICHTEN, beide gewollt:
 *
 *  • Ohne `require_heartbeat` im signierten Token gibt es nichts zu prüfen — und
 *    damit auch keinen Fern-Widerruf. Das ist die Falle, an der eine
 *    Kundenlizenz fünf Wochen lang scharf AUSSAH und wirkungslos war: Gate an,
 *    Manifest frisch, Widerruf ohne Wirkung.
 *  • Ein gerade gestarteter Dienst (noch kein Zustand) wird nicht gesperrt.
 *    Sonst sperrte jeder Neustart, bis der erste Lauf durch ist.
 */
export function sperrgrund(zustand, jetzt, karenzTage, brauchtHeartbeat) {
  if (!brauchtHeartbeat) return null;
  if (zustand === null || zustand === undefined) return null;
  if (zustand.letzterStatus === 'widerrufen') return 'widerrufen';

  const karenzMs = Math.max(0, karenzTage) * 86400000;
  if (zustand.letzteOkPruefung != null) {
    return (jetzt - zustand.letzteOkPruefung) > karenzMs ? 'pruefung_ueberfaellig' : null;
  }
  if (zustand.pendingSeit != null && (jetzt - zustand.pendingSeit) > karenzMs) {
    return 'pruefung_ueberfaellig';
  }
  return null;
}
