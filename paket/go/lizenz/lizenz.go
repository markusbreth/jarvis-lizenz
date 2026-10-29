// Package lizenz ist der geteilte Kern der JARVIS-Lizenzpruefung (Go-Bauart).
//
// Reine Zustandsmaschine: KEINE Netzaufrufe, KEINE Datenbank, KEINE Uhr. Alles
// Veraenderliche kommt als Argument herein. Genau das macht sie gegen dieselben
// Faelle messbar wie die Python- und die JS-Bauart.
//
// Was der Kern entscheidet, steht in VERTRAG.md; was er ausdruecklich NICHT
// entscheidet (403 gegen Nur-Lese gegen Weiterleitung, welche Pfade frei
// bleiben, ob GET durchgeht) ebenfalls.
//
// Wortgleich zur Python- und JS-Bauart — Abweichungen im Verhalten faengt
// pruefstand/laeufer.sh.
package lizenz

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrLizenz — Token oder Manifest ist unlesbar oder falsch signiert.
var ErrLizenz = errors.New("lizenz")

// ErrSchluesselUnbekannt — die Nutzlast nennt ein `kid`, das im Schluesselring
// nicht steht (seit 0.2.0). Ist zugleich ein ErrLizenz.
var ErrSchluesselUnbekannt = fmt.Errorf("%w: schluessel_unbekannt", ErrLizenz)

// kettenFehler — Erneuerungskette richtig signiert, aber ausserhalb ihrer
// Berechtigung. Grund ist der token_grund.
type kettenFehler struct{ grund string }

func (k kettenFehler) Error() string { return k.grund }

// BerechtigungMaxTage — so lange gilt eine Berechtigung fuer den
// Erneuerungsschluessel hoechstens (seit 0.2.0). 366 statt 365, damit ein Jahr
// mit Schalttag hineinpasst.
const BerechtigungMaxTage = 366

const tag = 24 * time.Hour

// Ring ist ein Schluesselring `kid → PEM` (seit 0.2.0).
type Ring map[string]string

// schluessel ist ein einzelnes PEM (wie in 0.1) ODER ein Ring.
type schluessel struct {
	pem  string
	ring Ring
}

// Signierte Objekte, die KEIN Token sind. Beide sind oeffentlich (das Manifest
// holt jede Installation, die Berechtigung steckt in jedem erneuerten Token),
// beide tragen `product` und kein `expires_at` bzw. ein langes — als Token
// vorgelegt waeren sie eine unbefristete Lizenz ohne Heartbeat gewesen.
func keinToken(nutzlast map[string]any) bool {
	t, _ := nutzlast["type"].(string)
	return t == "license-manifest" || t == "erneuerungs-berechtigung"
}

func b64urlDec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// ZeitLesen liest ISO-8601 mit oder ohne `Z`. Unlesbar → Nullzeit + false.
//
// NIE gegen die Epoche rechnen: ein unlesbarer Zeitstempel als 0 zu lesen ergibt
// "vor 496573 Stunden" und damit einen roten Fehlalarm. Diese Falle ist im
// Maschinenraum zweimal aufgetreten; hier ist sie durch das zweite Ergebnis
// abgeschnitten — der Aufrufer muss den Fall benennen.
func ZeitLesen(wert string) (time.Time, bool) {
	w := strings.TrimSpace(wert)
	if w == "" {
		return time.Time{}, false
	}
	for _, form := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(form, w); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func teile(draht string) ([]byte, []byte, error) {
	t := strings.Split(strings.TrimSpace(draht), ".")
	if len(t) != 2 || t[0] == "" || t[1] == "" {
		return nil, nil, ErrLizenz
	}
	roh, err := b64urlDec(t[0])
	if err != nil {
		return nil, nil, ErrLizenz
	}
	sig, err := b64urlDec(t[1])
	if err != nil {
		return nil, nil, ErrLizenz
	}
	return roh, sig, nil
}

func jsonObjekt(roh []byte) (map[string]any, error) {
	var nutzlast map[string]any
	if err := json.Unmarshal(roh, &nutzlast); err != nil || nutzlast == nil {
		return nil, ErrLizenz
	}
	return nutzlast, nil
}

func verifiziere(roh, sig []byte, pubkeyPEM string) error {
	block, _ := pem.Decode([]byte(pubkeyPEM))
	if block == nil {
		return ErrLizenz
	}
	roher, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrLizenz
	}
	pub, ok := roher.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, roh, sig) {
		return ErrLizenz
	}
	return nil
}

// pruefeSignatur: `b64url(nutzlast).b64url(signatur)` → Nutzlast.
//
// Verifiziert wird ueber die DEKODIERTEN Bytes, nicht ueber eine
// Neuserialisierung — sonst koennten Unterschiede in Leerzeichen oder
// Schluesselreihenfolge eine gueltige Signatur brechen.
//
// Mit einem einzelnen PEM wie in 0.1 — ein `kid` in der Nutzlast wird dann
// nicht gelesen. Mit einem Ring (seit 0.2.0) entscheidet das `kid` der
// Nutzlast, welcher Schluessel prueft; ein `kid`, das nicht im Ring steht, ist
// ErrSchluesselUnbekannt. Ohne `kid` (Altbestand) darf jeder Schluessel passen.
func pruefeSignatur(draht string, s schluessel) (map[string]any, error) {
	roh, sig, err := teile(draht)
	if err != nil {
		return nil, err
	}
	if s.ring == nil {
		if err := verifiziere(roh, sig, s.pem); err != nil {
			return nil, err
		}
		return jsonObjekt(roh)
	}
	nutzlast, err := jsonObjekt(roh)
	if err != nil {
		return nil, err
	}
	kidRoh, da := nutzlast["kid"]
	if !da || kidRoh == nil {
		for _, p := range s.ring {
			if verifiziere(roh, sig, p) == nil {
				return nutzlast, nil
			}
		}
		return nil, ErrLizenz
	}
	kid, istText := kidRoh.(string)
	p, bekannt := s.ring[kid]
	if !istText || !bekannt {
		return nil, ErrSchluesselUnbekannt
	}
	if err := verifiziere(roh, sig, p); err != nil {
		return nil, err
	}
	return nutzlast, nil
}

// ganzPositiv — wie `_ganz_positiv` in Python und `Number.isInteger` in JS.
func ganzPositiv(x any) (int, bool) {
	f, ok := x.(float64)
	if !ok || f <= 0 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

func zeitFeld(m map[string]any, feld string) (time.Time, bool) {
	if s, ok := m[feld].(string); ok {
		return ZeitLesen(s)
	}
	return time.Time{}, false
}

// kette prueft die Erneuerungskette (seit 0.2.0). Zweiter Wert false: das
// Token hat keine Kette.
//
// Ein Token mit `berechtigung` ist NICHT vom Hauptschluessel signiert, sondern
// vom Erneuerungsschluessel des Lizenzdienstes. Die Berechtigung ist ein vom
// Hauptschluessel signiertes Objekt, das den Erneuerungsschluessel nennt und
// begrenzt: hoechstens BerechtigungMaxTage gueltig, Tokens hoechstens
// `max_token_tage` lang, nur fuer `product`. Ein kompromittierter Dienst kann
// so hoechstens kurze Tokens ausstellen — nie ein unbefristetes.
//
// Die Reihenfolge der Pruefungen ist Teil des Vertrags (alle drei Bauarten
// gleich): Signaturen → Produkt → Berechtigung → Laufzeit → Zeitfenster.
// Gemessen wird `issued_at` des Tokens gegen das Fenster der Berechtigung,
// nicht die Uhr: laeuft die Berechtigung ab, bleiben schon ausgestellte Tokens
// ihre kurze Laufzeit gueltig, statt alle Kunden im selben Augenblick zu sperren.
func kette(token string, s schluessel, produkt string) (map[string]any, bool, error) {
	roh, sig, err := teile(token)
	if err != nil {
		return nil, false, err
	}
	vorab, err := jsonObjekt(roh)
	if err != nil {
		return nil, false, nil
	}
	bRoh, da := vorab["berechtigung"]
	if !da {
		return nil, false, nil
	}
	bDraht, ok := bRoh.(string)
	if !ok {
		return nil, true, ErrLizenz
	}
	b, err := pruefeSignatur(bDraht, s)
	if err != nil {
		return nil, true, err
	}
	if t, _ := b["type"].(string); t != "erneuerungs-berechtigung" {
		return nil, true, ErrLizenz
	}
	pk, ok := b["pubkey"].(string)
	if !ok {
		return nil, true, ErrLizenz
	}
	if err := verifiziere(roh, sig, pk); err != nil {
		return nil, true, err
	}
	if p, _ := b["product"].(string); p != produkt || b["product"] == nil {
		return nil, true, kettenFehler{"falsches_produkt"}
	}
	bVon, gutVon := zeitFeld(b, "issued_at")
	bBis, gutBis := zeitFeld(b, "expires_at")
	maxTage, gutMax := ganzPositiv(b["max_token_tage"])
	if !gutVon || !gutBis || bBis.Before(bVon) ||
		bBis.Sub(bVon) > BerechtigungMaxTage*tag || !gutMax {
		return nil, true, kettenFehler{"berechtigung_ungueltig"}
	}
	tVon, gutTVon := zeitFeld(vorab, "issued_at")
	tBis, gutTBis := zeitFeld(vorab, "expires_at")
	if !gutTVon || !gutTBis || tBis.Before(tVon) || tBis.Sub(tVon) > time.Duration(maxTage)*tag {
		return nil, true, kettenFehler{"laufzeit_ueberschritten"}
	}
	if tVon.Before(bVon) || tVon.After(bBis) {
		return nil, true, kettenFehler{"berechtigung_abgelaufen"}
	}
	return vorab, true, nil
}

// ── 1. Das Token ────────────────────────────────────────────────────────────

// TokenUrteil ist die Offline-Aussage ueber ein Token.
type TokenUrteil struct {
	Gueltig bool
	Grund   string // ok | fehlt | ungueltig | falsches_produkt | abgelaufen | offline_ohne_ablauf
	// seit 0.2.0 auch: schluessel_unbekannt | berechtigung_ungueltig
	//                  | laufzeit_ueberschritten | berechtigung_abgelaufen
	Nutzlast map[string]any
}

// LizenzID gibt die Kennung, unter der widerrufen wird — oder nil.
func (t TokenUrteil) LizenzID() *string {
	if w, ok := t.Nutzlast["license_id"]; ok && w != nil {
		if s, ok := w.(string); ok {
			return &s
		}
	}
	return nil
}

// BrauchtHeartbeat sagt, ob der Fern-Widerruf ueberhaupt greift.
func (t TokenUrteil) BrauchtHeartbeat() bool {
	b, _ := t.Nutzlast["require_heartbeat"].(bool)
	return b
}

// Offline sagt, ob das Token eine ausdruecklich ausgestellte Offline-Lizenz
// ist (seit 0.2.0).
func (t TokenUrteil) Offline() bool {
	b, _ := t.Nutzlast["offline"].(bool)
	return b
}

// Anker ist `issued_at` — ab hier zaehlt SperrgrundKunde ohne Zustand
// (seit 0.2.0). nil, wenn nicht lesbar.
func (t TokenUrteil) Anker() *time.Time {
	if s, ok := t.Nutzlast["issued_at"].(string); ok {
		if a, gut := ZeitLesen(s); gut {
			return &a
		}
	}
	return nil
}

// tokenAblauf liest `expires_at`; false, wenn es fehlt oder unlesbar ist.
func tokenAblauf(nutzlast map[string]any) (time.Time, bool) {
	if s, ok := nutzlast["expires_at"].(string); ok {
		return ZeitLesen(s)
	}
	return time.Time{}, false
}

// PruefeToken entscheidet die Offline-Gueltigkeit: Signatur, Produkt, Ablauf.
// Grenzen (max_*) bleiben beim Produkt — sie heissen dort verschieden.
func PruefeToken(token, pubkeyPEM, produkt string, jetzt time.Time) TokenUrteil {
	return pruefeToken(token, schluessel{pem: pubkeyPEM}, produkt, jetzt)
}

// PruefeTokenRing ist PruefeToken mit Schluesselring (seit 0.2.0). Eine
// eigene Funktion statt eines neuen Parameters, damit kein Aufrufer von 0.1
// bricht. Ein nil-Ring zaehlt als leerer Ring.
func PruefeTokenRing(token string, ring Ring, produkt string, jetzt time.Time) TokenUrteil {
	if ring == nil {
		ring = Ring{}
	}
	return pruefeToken(token, schluessel{ring: ring}, produkt, jetzt)
}

func pruefeToken(token string, s schluessel, produkt string, jetzt time.Time) TokenUrteil {
	if strings.TrimSpace(token) == "" {
		return TokenUrteil{false, "fehlt", map[string]any{}}
	}
	nutzlast, istKette, err := kette(token, s, produkt)
	if err == nil && !istKette {
		nutzlast, err = pruefeSignatur(token, s)
		if err == nil && keinToken(nutzlast) {
			return TokenUrteil{false, "ungueltig", map[string]any{}}
		}
	}
	if err != nil {
		var kf kettenFehler
		switch {
		case errors.Is(err, ErrSchluesselUnbekannt):
			return TokenUrteil{false, "schluessel_unbekannt", map[string]any{}}
		case errors.As(err, &kf):
			return TokenUrteil{false, kf.grund, map[string]any{}}
		}
		return TokenUrteil{false, "ungueltig", map[string]any{}}
	}
	// nil/fehlend wird geduldet: Tokens aus der Zeit vor der Console trugen das
	// Feld nicht. Ein FALSCHES Produkt wird abgewiesen — darum geht es.
	if p, da := nutzlast["product"]; da && p != nil {
		if s, ok := p.(string); !ok || s != produkt {
			return TokenUrteil{false, "falsches_produkt", nutzlast}
		}
	}
	ablauf, gut := tokenAblauf(nutzlast)
	// Seit 0.2.0: ohne Heartbeat UND ohne Ablauf schuetzte nur noch der
	// Vertrag — das „Offline-Perpetual", das es nicht geben soll.
	if off, _ := nutzlast["offline"].(bool); off && !gut {
		return TokenUrteil{false, "offline_ohne_ablauf", nutzlast}
	}
	if gut && jetzt.After(ablauf) {
		return TokenUrteil{false, "abgelaufen", nutzlast}
	}
	return TokenUrteil{true, "ok", nutzlast}
}

// PruefeBindung sagt, ob das Token zu DIESER Installation gehoert (seit 0.2.0):
// "ungebunden" (keine `install_id` im Token; was dann gilt, entscheidet das
// Produkt), "ok" (gebunden und gleich) oder "fremd" (gebunden und anders,
// ODER die Installation kennt ihre eigene Kennung nicht).
func PruefeBindung(nutzlast map[string]any, installID *string) string {
	soll, da := nutzlast["install_id"]
	if !da || soll == nil || soll == "" {
		return "ungebunden"
	}
	// Nur eine Zeichenkette bindet — eine Zahl oder Liste schriebe jede
	// Sprache anders als Text, und die Bauarten kaemen zu verschiedenen Urteilen.
	s, istText := soll.(string)
	if !istText || installID == nil || *installID == "" {
		return "fremd"
	}
	if s == *installID {
		return "ok"
	}
	return "fremd"
}

// WirksameZeit ist die Uhr, aber nie vor der Hochwassermarke des Aufrufers
// (seit 0.2.0). Eine zurueckgestellte Uhr verlaengert so weder Ablauf noch
// Karenz; sie wird GEMELDET (zweiter Wert), nicht bestraft.
func WirksameZeit(uhr time.Time, marke *time.Time) (time.Time, bool) {
	if marke == nil || !uhr.Before(*marke) {
		return uhr, false
	}
	return *marke, true
}

// ── 2. Das Manifest ─────────────────────────────────────────────────────────

// ManifestUrteil ist die Online-Aussage. JEDE Stoerung ist "unbekannt" — damit
// greift die Karenzzeit, statt sofort zu sperren.
type ManifestUrteil struct {
	Status       string // aktiv | widerrufen | unbekannt
	Detail       string
	Seq          *int
	Entitlements map[string]any
}

// BewerteManifest bewertet das signierte Manifest. Gibt nie einen Fehler
// zurueck: "widerrufen" gibt es nur bei einem ausdruecklichen Eintrag.
//
// `roh == nil` heisst nicht erreichbar (Netz, DNS, Zeitueberschreitung). Der
// Aufrufer holt das Manifest; dass er dabei scheitern kann, ist keine Aussage
// ueber die Lizenz.
func BewerteManifest(roh *string, pubkeyPEM string, lizenzID *string,
	jetzt time.Time, letzteSeq *int) ManifestUrteil {
	return bewerteManifest(roh, schluessel{pem: pubkeyPEM}, lizenzID, jetzt, letzteSeq)
}

// BewerteManifestRing ist BewerteManifest mit Schluesselring (seit 0.2.0).
func BewerteManifestRing(roh *string, ring Ring, lizenzID *string,
	jetzt time.Time, letzteSeq *int) ManifestUrteil {
	if ring == nil {
		ring = Ring{}
	}
	return bewerteManifest(roh, schluessel{ring: ring}, lizenzID, jetzt, letzteSeq)
}

func bewerteManifest(roh *string, s schluessel, lizenzID *string,
	jetzt time.Time, letzteSeq *int) ManifestUrteil {

	if roh == nil {
		return ManifestUrteil{Status: "unbekannt", Detail: "unerreichbar"}
	}
	m, err := pruefeSignatur(*roh, s)
	if errors.Is(err, ErrSchluesselUnbekannt) {
		return ManifestUrteil{Status: "unbekannt", Detail: "schluessel_unbekannt"}
	}
	if err != nil {
		return ManifestUrteil{Status: "unbekannt", Detail: "signatur_falsch"}
	}
	if t, _ := m["type"].(string); t != "license-manifest" {
		return ManifestUrteil{Status: "unbekannt", Detail: "kein_manifest"}
	}
	// Frischegrenze, kein Ablaufdatum: einem alten Stand wird nicht vertraut,
	// sonst koennte ein Kunde ihn einfrieren, um einem Widerruf zu entgehen.
	if s, ok := m["valid_until"].(string); ok {
		if bis, gut := ZeitLesen(s); gut && jetzt.After(bis) {
			return ManifestUrteil{Status: "unbekannt", Detail: "veraltet"}
		}
	}
	// JSON-Zahlen sind in Go float64. Nur ganzzahlige zaehlen — wie
	// `isinstance(seq, int)` in Python und `Number.isInteger` in JS.
	var seq *int
	if f, ok := m["seq"].(float64); ok && f == float64(int(f)) {
		i := int(f)
		seq = &i
	}
	if seq != nil && letzteSeq != nil && *seq < *letzteSeq {
		return ManifestUrteil{Status: "unbekannt", Detail: "rueckrollung"}
	}
	if lizenzID == nil {
		return ManifestUrteil{Status: "unbekannt", Detail: "keine_lizenz_id", Seq: seq}
	}
	if liste, ok := m["revoked"].([]any); ok {
		for _, e := range liste {
			if s, ok := e.(string); ok && s == *lizenzID {
				return ManifestUrteil{Status: "widerrufen", Detail: "widerrufen", Seq: seq}
			}
		}
	}
	bekannt, _ := m["licenses"].(map[string]any)
	eintrag, da := bekannt[*lizenzID]
	if !da {
		// HAERTUNG 3: Abwesenheit ist NICHT massgeblich. Ein gueltig signiertes,
		// aber unvollstaendiges Manifest darf keinen zahlenden Kunden lahmlegen.
		return ManifestUrteil{Status: "unbekannt", Detail: "nicht_aufgefuehrt", Seq: seq}
	}
	ent, _ := eintrag.(map[string]any)
	if ent == nil {
		ent = map[string]any{}
	}
	return ManifestUrteil{Status: "aktiv", Detail: "ok", Seq: seq, Entitlements: ent}
}

// ── 3. Der Zustand ──────────────────────────────────────────────────────────

// Zustand ist, was zwischen zwei Laeufen ueberdauert. Der Aufrufer legt ihn ab,
// wo er will.
type Zustand struct {
	LetzterStatus    string
	LetzteOkPruefung *time.Time
	PendingSeit      *time.Time
	ManifestSeq      *int
	Entitlements     map[string]any
}

// NaechsterZustand rechnet den neuen Zustand. Rein — der alte bleibt unberuehrt.
//
// Hier stecken zwei der drei Haertungen, und beide sind Einbahnstrassen:
//
// HAERTUNG 2 — "widerrufen" KLEBT. Ein "unbekannt" (Netz gekappt, Signatur
// kaputt) darf einen bestaetigten Widerruf nicht loeschen, sonst "ent-widerruft"
// das Ziehen des Netzsteckers die Lizenz fuer die ganze Karenzzeit. Nur ein
// frisches "aktiv" loescht ihn.
//
// HAERTUNG 1 — PendingSeit ist der STABILE Anker. Beim ersten Misserfolg
// gesetzt, danach unangetastet. Wuerde stattdessen "zuletzt versucht" gezaehlt,
// schoebe jeder Fehlversuch die Frist vor sich her und sie liefe nie ab.
func NaechsterZustand(alt Zustand, urteil ManifestUrteil, jetzt time.Time) Zustand {
	neu := Zustand{
		LetzterStatus:    urteil.Status,
		LetzteOkPruefung: alt.LetzteOkPruefung,
		PendingSeit:      alt.PendingSeit,
		ManifestSeq:      alt.ManifestSeq,
		Entitlements:     alt.Entitlements,
	}
	if alt.LetzterStatus == "widerrufen" && urteil.Status == "unbekannt" {
		neu.LetzterStatus = "widerrufen"
	}
	if urteil.Seq != nil && (neu.ManifestSeq == nil || *urteil.Seq > *neu.ManifestSeq) {
		neu.ManifestSeq = urteil.Seq
	}
	if urteil.Status == "aktiv" {
		j := jetzt
		neu.LetzteOkPruefung = &j
		neu.PendingSeit = nil
		if urteil.Entitlements != nil {
			neu.Entitlements = urteil.Entitlements
		}
	} else if neu.PendingSeit == nil {
		j := jetzt
		neu.PendingSeit = &j
	}
	return neu
}

// Sperrgrund gibt "" · "widerrufen" · "pruefung_ueberfaellig".
//
// ZWEI NACHSICHTEN, beide gewollt:
//
//   - Ohne require_heartbeat im signierten Token gibt es nichts zu pruefen — und
//     damit auch keinen Fern-Widerruf. Das ist die Falle, an der eine
//     Kundenlizenz fuenf Wochen lang scharf AUSSAH und wirkungslos war: Gate an,
//     Manifest frisch, Widerruf ohne Wirkung.
//   - Ein gerade gestarteter Dienst (noch kein Zustand) wird nicht gesperrt.
//     Sonst sperrte jeder Neustart, bis der erste Lauf durch ist.
func Sperrgrund(zustand *Zustand, jetzt time.Time, karenzTage int,
	brauchtHeartbeat bool) string {

	if !brauchtHeartbeat || zustand == nil {
		return ""
	}
	if zustand.LetzterStatus == "widerrufen" {
		return "widerrufen"
	}
	if karenzTage < 0 {
		karenzTage = 0
	}
	karenz := time.Duration(karenzTage) * 24 * time.Hour
	if zustand.LetzteOkPruefung != nil {
		if jetzt.Sub(*zustand.LetzteOkPruefung) > karenz {
			return "pruefung_ueberfaellig"
		}
		return ""
	}
	if zustand.PendingSeit != nil && jetzt.Sub(*zustand.PendingSeit) > karenz {
		return "pruefung_ueberfaellig"
	}
	return ""
}

// SperrgrundKunde ist Sperrgrund im KUNDEN-MODUS (seit 0.2.0): die zweite
// Nachsicht faellt. Solange es keinen erfolgreichen Lauf gibt, zaehlt die
// Karenz ab dem FRUEHEREN von `PendingSeit` und `anker` (das `issued_at` des
// Tokens). Nur ab `PendingSeit` zu zaehlen reichte nicht: ein geloeschter
// Zustand plus ein gesperrter Lizenzserver setzte `PendingSeit` im naechsten
// Lauf auf „jetzt" und schenkte eine frische Karenz, beliebig oft. Ohne
// lesbaren Anker sperrt der Kunden-Modus sofort; eine `LetzteOkPruefung` in
// der Zukunft gilt als fehlend. Eine eigene Funktion statt eines neuen
// Parameters, damit kein Aufrufer von 0.1 bricht.
func SperrgrundKunde(zustand *Zustand, jetzt time.Time, karenzTage int,
	brauchtHeartbeat bool, anker *time.Time) string {

	if !brauchtHeartbeat {
		return ""
	}
	if karenzTage < 0 {
		karenzTage = 0
	}
	karenz := time.Duration(karenzTage) * 24 * time.Hour
	if zustand != nil && zustand.LetzterStatus == "widerrufen" {
		return "widerrufen"
	}
	if zustand != nil && zustand.LetzteOkPruefung != nil && !zustand.LetzteOkPruefung.After(jetzt) {
		if jetzt.Sub(*zustand.LetzteOkPruefung) > karenz {
			return "pruefung_ueberfaellig"
		}
		return ""
	}
	if anker == nil {
		return "pruefung_ueberfaellig"
	}
	start := *anker
	if zustand != nil && zustand.PendingSeit != nil && zustand.PendingSeit.Before(start) {
		start = *zustand.PendingSeit
	}
	if jetzt.Sub(start) > karenz {
		return "pruefung_ueberfaellig"
	}
	return ""
}
