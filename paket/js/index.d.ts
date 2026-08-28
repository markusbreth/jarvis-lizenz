/**
 * Typen des geteilten Kerns.
 *
 * Der Kern selbst ist bewusst reines CommonJS-JavaScript: er soll aus Python,
 * Go und Node gleich aussehen und in Produkten ohne Build-Schritt laufen. Diese
 * Datei liegt daneben, damit die TypeScript-Produkte der Familie ihn benutzen
 * koennen, ohne sich jeweils eine eigene Deklaration zu schreiben.
 *
 * WARUM SIE MITGELIEFERT WIRD (28.08.2026): Catering OS war das erste
 * TypeScript-Produkt am Kern, und dort ging es ohne nicht — `tsc` bricht mit
 * TS7016 ab, und die naheliegende Abhilfe (eine lokale `.d.ts` per
 * `/// <reference>`) verbietet die Hausregel des Repos
 * (`@typescript-eslint/triple-slash-reference`). Eine Deklaration je Produkt
 * waere ausserdem genau das, wogegen dieses Paket gebaut ist: dieselbe Sache an
 * sechs Stellen, die auseinanderlaufen koennen.
 *
 * `unknown` statt `any` in der Nutzlast ist Absicht. Sie kommt aus einem
 * signierten, aber FREMDEN JSON — wer sie benutzt, soll pruefen muessen, was
 * drinsteht. Ein `any` hier haette die Pruefung stillschweigend erlassen.
 */

/** Der Fehler, den `_pruefeSignatur` wirft. Alle oeffentlichen Funktionen fangen ihn. */
export class LizenzFehler extends Error {}

/** ISO-8601 lesen; `null` bei fehlendem oder unlesbarem Wert. */
export function zeitLesen(wert: unknown): Date | null;

export type TokenUrteil = {
  gueltig: boolean;
  /** `ok` · `fehlt` · `ungueltig` · `falsches_produkt` · `abgelaufen` */
  grund: string;
  /** Die decodierte Nutzlast. Bei `fehlt`/`ungueltig` leer. */
  nutzlast: Record<string, unknown>;
  lizenzId: string | null;
  /** Ob der Fern-Widerruf ueberhaupt greift — steht IM signierten Token. */
  brauchtHeartbeat: boolean;
};

/** Offline-Gueltigkeit: Signatur, Produkt, Ablauf. Grenzen bleiben beim Produkt. */
export function pruefeToken(
  token: string,
  pubkeyPem: string,
  produkt: string,
  jetzt: Date,
): TokenUrteil;

export type ManifestUrteil = {
  /** `aktiv` · `widerrufen` · `unbekannt` */
  status: string;
  /**
   * `ok` · `widerrufen` · `unerreichbar` · `signatur_falsch` · `kein_manifest`
   * · `veraltet` · `rueckrollung` · `nicht_aufgefuehrt` · `keine_lizenz_id`
   */
  detail: string;
  seq: number | null;
  entitlements: Record<string, unknown> | null;
};

/**
 * Das signierte Manifest bewerten. Wirft nie.
 *
 * `roh === null` heisst NICHT ERREICHBAR — der Aufrufer holt das Manifest, und
 * dass er dabei scheitern kann, ist keine Aussage ueber die Lizenz.
 */
export function bewerteManifest(
  roh: string | null | undefined,
  pubkeyPem: string,
  lizenzId: string | null,
  jetzt: Date,
  letzteSeq: number | null,
): ManifestUrteil;

export type Zustand = {
  /** In der Sprache des Kerns: `aktiv` · `widerrufen` · `unbekannt` */
  letzterStatus: string | null;
  letzteOkPruefung: Date | null;
  /** Der STABILE Anker der Karenzzeit — nicht „zuletzt versucht". */
  pendingSeit: Date | null;
  manifestSeq: number | null;
  entitlements?: Record<string, unknown> | null;
};

/** Den neuen Zustand rechnen. Rein — der alte bleibt unberuehrt. */
export function naechsterZustand(
  alt: Zustand,
  urteil: ManifestUrteil,
  jetzt: Date,
): Zustand;

/** `widerrufen` · `pruefung_ueberfaellig` · `""` (kein Grund zu sperren). */
export function sperrgrund(
  zustand: Zustand | null,
  jetzt: Date,
  karenzTage: number,
  brauchtHeartbeat: boolean,
): string;

declare const kern: {
  LizenzFehler: typeof LizenzFehler;
  zeitLesen: typeof zeitLesen;
  pruefeToken: typeof pruefeToken;
  bewerteManifest: typeof bewerteManifest;
  naechsterZustand: typeof naechsterZustand;
  sperrgrund: typeof sperrgrund;
};
export default kern;
