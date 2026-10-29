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

/** Die Nutzlast nennt ein `kid`, das im Schluesselring nicht steht (seit 0.2.0). */
export class SchluesselUnbekannt extends LizenzFehler {}

/** Hoechste Gueltigkeit einer Berechtigung fuer den Erneuerungsschluessel, in Tagen (seit 0.2.0). */
export const BERECHTIGUNG_MAX_TAGE: number;

/**
 * Ein PEM (wie in 0.1 — ein `kid` in der Nutzlast wird dann nicht gelesen)
 * oder seit 0.2.0 ein Schluesselring `{kid: PEM}`: das `kid` der Nutzlast
 * waehlt den Schluessel, ohne `kid` darf jeder des Rings passen.
 */
export type Schluessel = string | Record<string, string>;

/** ISO-8601 lesen; `null` bei fehlendem oder unlesbarem Wert. */
export function zeitLesen(wert: unknown): Date | null;

export type TokenUrteil = {
  gueltig: boolean;
  /**
   * `ok` · `fehlt` · `ungueltig` · `falsches_produkt` · `abgelaufen`
   * · `offline_ohne_ablauf` · `schluessel_unbekannt` · `berechtigung_ungueltig`
   * · `laufzeit_ueberschritten` · `berechtigung_abgelaufen` (alle seit 0.2.0)
   */
  grund: string;
  /** Die decodierte Nutzlast. Bei `fehlt`/`ungueltig` leer. */
  nutzlast: Record<string, unknown>;
  lizenzId: string | null;
  /** Ob der Fern-Widerruf ueberhaupt greift — steht IM signierten Token. */
  brauchtHeartbeat: boolean;
  /**
   * Ausdruecklich ausgestellte Offline-Lizenz (`offline: true`, seit 0.2.0).
   * Optional nur im Typ: der Kern liefert das Feld immer. Als Pflichtfeld
   * braeche es jede selbstgebaute `TokenUrteil`-Attrappe in den Produkten bei
   * der Uebernahme von 0.2.0 (Durchsicht 27.10.2026).
   */
  offline?: boolean;
  /** `issued_at` — ab hier zaehlt der Kunden-Modus ohne Zustand (seit 0.2.0). Optional wie `offline`. */
  anker?: Date | null;
};

/** Offline-Gueltigkeit: Signatur, Produkt, Ablauf. Grenzen bleiben beim Produkt. */
export function pruefeToken(
  token: string,
  pubkeyPem: Schluessel,
  produkt: string,
  jetzt: Date,
): TokenUrteil;

export type ManifestUrteil = {
  /** `aktiv` · `widerrufen` · `unbekannt` */
  status: string;
  /**
   * `ok` · `widerrufen` · `unerreichbar` · `signatur_falsch` · `kein_manifest`
   * · `veraltet` · `rueckrollung` · `nicht_aufgefuehrt` · `keine_lizenz_id`
   * · `schluessel_unbekannt` (seit 0.2.0)
   */
  detail: string;
  seq: number | null;
  entitlements: Record<string, unknown> | null;
};

/**
 * Gehoert das Token zu DIESER Installation? (seit 0.2.0)
 * `ungebunden` (keine `install_id` im Token) · `ok` · `fremd` (anders, oder die
 * Installation kennt ihre eigene Kennung nicht).
 */
export function pruefeBindung(
  nutzlast: Record<string, unknown> | null | undefined,
  installId: string | null | undefined,
): 'ungebunden' | 'ok' | 'fremd';

/**
 * Die Uhr, aber nie vor der Hochwassermarke des Aufrufers (seit 0.2.0). Eine
 * zurueckgestellte Uhr wird gemeldet, nicht bestraft.
 */
export function wirksameZeit(
  uhr: Date,
  marke: Date | null | undefined,
): { jetzt: Date; zurueckgestellt: boolean };

/**
 * Das signierte Manifest bewerten. Wirft nie.
 *
 * `roh === null` heisst NICHT ERREICHBAR — der Aufrufer holt das Manifest, und
 * dass er dabei scheitern kann, ist keine Aussage ueber die Lizenz.
 */
export function bewerteManifest(
  roh: string | null | undefined,
  pubkeyPem: Schluessel,
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

/** Seit 0.2.0. Ohne Angabe verhaelt sich `sperrgrund` wie in 0.1. */
export type SperrOptionen = {
  /**
   * Ohne erfolgreichen Lauf zaehlt die Karenz ab dem frueheren von
   * `pendingSeit` und `anker`; ohne gueltigen Anker (auch ein ungueltiges
   * `Date`) sofort `pruefung_ueberfaellig`. Eine `letzteOkPruefung` in der
   * Zukunft gilt als fehlend.
   */
  kundenModus?: boolean;
  /** In der Regel `TokenUrteil.anker`. */
  anker?: Date | null;
};

/** `widerrufen` · `pruefung_ueberfaellig` · `""` (kein Grund zu sperren). */
export function sperrgrund(
  zustand: Zustand | null,
  jetzt: Date,
  karenzTage: number,
  brauchtHeartbeat: boolean,
  optionen?: SperrOptionen,
): string;

declare const kern: {
  LizenzFehler: typeof LizenzFehler;
  SchluesselUnbekannt: typeof SchluesselUnbekannt;
  BERECHTIGUNG_MAX_TAGE: number;
  zeitLesen: typeof zeitLesen;
  pruefeToken: typeof pruefeToken;
  pruefeBindung: typeof pruefeBindung;
  wirksameZeit: typeof wirksameZeit;
  bewerteManifest: typeof bewerteManifest;
  naechsterZustand: typeof naechsterZustand;
  sperrgrund: typeof sperrgrund;
};
export default kern;
