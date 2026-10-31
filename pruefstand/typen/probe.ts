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
  pruefeBindung,
  pruefeToken,
  rohSchluessel,
  sperrgrund,
  wirksameZeit,
  zeitLesen,
  BERECHTIGUNG_MAX_TAGE,
  type ManifestUrteil,
  type PruefOptionen,
  type Schluessel,
  type TokenUrteil,
  type Verifiziere,
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

// 6. Seit 0.2.0: Kunden-Modus, Bindung, Offline, Hochwassermarke.
// Beide sind im Typ optional (Attrappen in den Produkten), zur Laufzeit immer da.
const offline: boolean = urteil.offline ?? false;
const anker: Date | null = urteil.anker ?? null;
const bindung: 'ungebunden' | 'ok' | 'fremd' = pruefeBindung(urteil.nutzlast, 'inst-1');
const ohneKennung: string = pruefeBindung(urteil.nutzlast, null);
const wirksam: { jetzt: Date; zurueckgestellt: boolean } = wirksameZeit(jetzt, zeit);
const kundenSperre: string = sperrgrund(null, wirksam.jetzt, 7, heartbeat,
  { kundenModus: true, anker });
const ueberDefaultBindung: string = kern.pruefeBindung(null, 'inst-1');

// 7. Seit 0.2.0: Schluesselring statt eines PEM — fuer Token UND Manifest.
const ring: Schluessel = { k1: 'PEM', k2: 'PEM' };
const mitRing: TokenUrteil = pruefeToken('a.b', ring, 'produkt', jetzt);
const manifestRing: ManifestUrteil = bewerteManifest('a.b', ring, 'lic-1', jetzt, null);
const maxTage: number = BERECHTIGUNG_MAX_TAGE;

// 8. Seit 0.2.1: eingespeiste Pruefung — fuer Token UND Manifest.
const eigene: Verifiziere = (roh, sig, schluessel) =>
  roh.length > 0 && sig.length === 64 && schluessel.length === 32;
const optionen: PruefOptionen = { verifiziere: eigene };
const mitOption: TokenUrteil = pruefeToken('a.b', ring, 'produkt', jetzt, optionen);
const manifestOption: ManifestUrteil = bewerteManifest('a.b', 'PEM', 'lic-1', jetzt, null, optionen);
const roh32: Uint8Array = rohSchluessel('PEM');
const ueberDefaultRoh: Uint8Array = kern.rohSchluessel('PEM');

// Alles benutzen, damit `noUnusedLocals` nicht zuschlaegt und die Zeilen
// wirklich geprueft werden statt wegoptimiert.
export const summe = [
  gueltig, grund, lizenzId, heartbeat, kunde, m1.status, m2.detail, seq,
  neu.letzterStatus, sperre, keinZustand, ueberDefault.gueltig, zeit,
  offline, anker, bindung, ohneKennung, wirksam.zurueckgestellt, kundenSperre,
  ueberDefaultBindung, mitRing.grund, manifestRing.detail, maxTage,
  mitOption.grund, manifestOption.detail, roh32.length, ueberDefaultRoh.length,
].length;
