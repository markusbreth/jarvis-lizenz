#!/usr/bin/env node
// Der Prüfling der JS-Bauart: ein Fall auf stdin, ein Urteil auf stdout.
//
//     echo '<fall.json>' | node pruefling.mjs
//
// Die Schnittstelle ist absichtlich winzig und sprachneutral — sie ist das,
// woran sich die drei Bauarten messen lassen. Nicht ihre inneren Namen, nicht
// ihre Signaturen, sondern das Urteil über denselben Eingang.
//
// Wortgleich zu paket/py/pruefling.py. Beide sind bewusst dumm: alles, was hier
// entschieden würde, wäre eine Entscheidung, die der Prüfstand nicht sieht.

import { readFileSync } from 'node:fs';
import {
  pruefeToken, pruefeBindung, wirksameZeit, bewerteManifest, naechsterZustand,
  sperrgrund, zeitLesen,
} from './src/index.js';

const fall = JSON.parse(readFileSync(0, 'utf-8'));

// ISO mit `Z`, wie die Python-Bauart. `toISOString()` liefert Millisekunden, die
// dort nicht entstehen — abgeschnitten, sonst wäre die Schreibweise selbst ein
// Unterschied und der Vergleich meldete einen Befund, den es nicht gibt.
const iso = (d) => (d === null || d === undefined
  ? null
  : new Date(d).toISOString().replace(/\.\d{3}Z$/, 'Z'));

const uhr = zeitLesen(fall.jetzt);
if (uhr === null) {
  console.error("FALL KAPUTT: 'jetzt' ist nicht lesbar");
  process.exit(2);
}
// Seit 0.2.0: `uhr_marke` ist die Hochwassermarke des Aufrufers. Fehlt sie,
// ist `jetzt` die Uhr — wie in 0.1.
const zeit = wirksameZeit(uhr, zeitLesen(fall.uhr_marke ?? null));
const jetzt = zeit.jetzt;

const tok = pruefeToken(fall.token ?? '', fall.pubkey, fall.produkt, jetzt);

const zEin = fall.zustand ?? null;
const alt = zEin === null ? null : {
  letzterStatus: zEin.letzter_status ?? null,
  letzteOkPruefung: zeitLesen(zEin.letzte_ok_pruefung),
  pendingSeit: zeitLesen(zEin.pending_seit),
  manifestSeq: zEin.manifest_seq ?? null,
  entitlements: zEin.entitlements ?? null,
};

// Das Manifest wird nur bewertet, wenn es eines zu bewerten gibt. `null` heißt
// „nicht erreichbar" und ist ein gültiger Eingang — kein Fehler. Das Fehlen des
// Schlüssels dagegen heißt „diesmal gar nicht geprüft".
let m = null;
let neu = alt;
if (Object.prototype.hasOwnProperty.call(fall, 'manifest')) {
  m = bewerteManifest(fall.manifest ?? null, fall.pubkey, tok.lizenzId,
                      jetzt, alt ? alt.manifestSeq : null);
  neu = naechsterZustand(alt ?? {}, m, jetzt);
}

const grund = sperrgrund(neu, jetzt, Number(fall.karenz_tage ?? 7), tok.brauchtHeartbeat,
                         { kundenModus: fall.kunden_modus === true, anker: tok.anker });

const urteil = {
  token_gueltig: tok.gueltig,
  token_grund: tok.grund,
  manifest_status: m === null ? null : m.status,
  manifest_detail: m === null ? null : m.detail,
  zustand: neu === null ? null : {
    letzter_status: neu.letzterStatus ?? null,
    letzte_ok_pruefung: iso(neu.letzteOkPruefung),
    pending_seit: iso(neu.pendingSeit),
    manifest_seq: neu.manifestSeq ?? null,
  },
  sperrgrund: grund,
};
// Die Antworten von 0.2.0 nur, wenn der Fall sie erfragt (`erweitert`). So
// bleiben die Fälle von 0.1 Byte für Byte, was sie waren — sie sind der Beleg,
// dass 0.2.0 nichts an ihnen ändert.
if (fall.erweitert === true) {
  urteil.erweiterung = {
    bindung: Object.prototype.hasOwnProperty.call(fall, 'install_id')
      ? pruefeBindung(tok.nutzlast, fall.install_id) : null,
    offline: tok.offline,
    uhr_zurueckgestellt: zeit.zurueckgestellt,
  };
}

// Ohne Ersetzer-Array. `JSON.stringify(x, keys)` ist eine ERLAUBNISLISTE und
// filtert auch VERSCHACHTELTE Schlüssel weg — `zustand` kam damit als `{}`
// heraus, und 15 Fälle meldeten einen Unterschied, den es im Kern nicht gab.
// Sortiert wird ohnehin im Läufer, für alle Bauarten gleich.
process.stdout.write(JSON.stringify(urteil) + '\n');
