/**
 * Kontrollfall fuer die mitgelieferte `index.d.ts`.
 *
 * Eine falsche Deklaration ist SCHLIMMER als keine: sie prueft durch und luegt.
 * Wer sie danach benutzt, bekommt vom Compiler eine Zusicherung, die das
 * Laufzeitverhalten nicht deckt — und merkt es beim Kunden.
 *
 * Diese Datei benutzt jede oeffentliche Funktion so, wie ein Produkt sie
 * benutzt, und haelt die Ergebnisse gegen die deklarierten Typen. Sie wird
 * NICHT ausgefuehrt; `tsc --noEmit` ist die ganze Pruefung.
 *
 * Die Gegenprobe steht in der CI daneben: eine absichtlich falsche Zeile hier
 * MUSS `tsc` rot machen. Ohne sie waere nicht zu unterscheiden, ob die Typen
 * stimmen oder ob `tsc` nur nichts gefunden hat.
 */
import kern, {
  bewerteManifest,
  naechsterZustand,
  pruefeToken,
  sperrgrund,
  zeitLesen,
  type ManifestUrteil,
  type TokenUrteil,
  type Zustand,
} from '@markusbreth/jarvis-lizenz';

const jetzt = new Date();

// 1. Token — der Weg, den jedes Produkt geht.
const urteil: TokenUrteil = pruefeToken('a.b', 'PEM', 'produkt', jetzt);
const gueltig: boolean = urteil.gueltig;
const grund: string = urteil.grund;
const lizenzId: string | null = urteil.lizenzId;
const heartbeat: boolean = urteil.brauchtHeartbeat;
// Die Nutzlast ist `unknown` je Feld — absichtlich. Wer sie benutzt, prueft.
const kunde: string | null =
  typeof urteil.nutzlast.customer === 'string' ? urteil.nutzlast.customer : null;

// 2. Manifest — `null` heisst „nicht erreichbar", das MUSS erlaubt sein.
const m1: ManifestUrteil = bewerteManifest(null, 'PEM', lizenzId, jetzt, null);
const m2: ManifestUrteil = bewerteManifest('a.b', 'PEM', 'lic-1', jetzt, 7);
const seq: number | null = m2.seq;

// 3. Zustand und Sperrgrund.
const alt: Zustand = {
  letzterStatus: null,
  letzteOkPruefung: null,
  pendingSeit: null,
  manifestSeq: null,
};
const neu: Zustand = naechsterZustand(alt, m1, jetzt);
const sperre: string = sperrgrund(neu, jetzt, 7, heartbeat);
const keinZustand: string = sperrgrund(null, jetzt, 7, false);

// 4. Der Vorgabe-Export — so binden ihn Catering OS und Hotel OS ein.
const ueberDefault: TokenUrteil = kern.pruefeToken('a.b', 'PEM', 'produkt', jetzt);

// 5. Zeit lesen.
const zeit: Date | null = zeitLesen('2027-01-31T00:00:00Z');

// Alles benutzen, damit `noUnusedLocals` nicht zuschlaegt und die Zeilen
// wirklich geprueft werden statt wegoptimiert.
export const summe = [
  gueltig, grund, lizenzId, heartbeat, kunde, m1.status, m2.detail, seq,
  neu.letzterStatus, sperre, keinZustand, ueberDefault.gueltig, zeit,
].length;
