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
	"strings"
	"time"
)

// ErrLizenz — Token oder Manifest ist unlesbar oder falsch signiert.
var ErrLizenz = errors.New("lizenz")

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

// pruefeSignatur: `b64url(nutzlast).b64url(signatur)` → Nutzlast.
//
// Verifiziert wird ueber die DEKODIERTEN Bytes, nicht ueber eine
// Neuserialisierung — sonst koennten Unterschiede in Leerzeichen oder
// Schluesselreihenfolge eine gueltige Signatur brechen.
func pruefeSignatur(draht, pubkeyPEM string) (map[string]any, error) {
	teile := strings.Split(strings.TrimSpace(draht), ".")
	if len(teile) != 2 || teile[0] == "" || teile[1] == "" {
		return nil, ErrLizenz
	}
	roh, err := b64urlDec(teile[0])
	if err != nil {
		return nil, ErrLizenz
	}
	sig, err := b64urlDec(teile[1])
	if err != nil {
		return nil, ErrLizenz
	}
	block, _ := pem.Decode([]byte(pubkeyPEM))
	if block == nil {
		return nil, ErrLizenz
	}
	roher, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrLizenz
	}
	pub, ok := roher.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, roh, sig) {
		return nil, ErrLizenz
	}
	var nutzlast map[string]any
	if err := json.Unmarshal(roh, &nutzlast); err != nil || nutzlast == nil {
		return nil, ErrLizenz
	}
	return nutzlast, nil
}

// ── 1. Das Token ────────────────────────────────────────────────────────────

// TokenUrteil ist die Offline-Aussage ueber ein Token.
type TokenUrteil struct {
	Gueltig  bool
	Grund    string // ok | fehlt | ungueltig | falsches_produkt | abgelaufen
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

// PruefeToken entscheidet die Offline-Gueltigkeit: Signatur, Produkt, Ablauf.
// Grenzen (max_*) bleiben beim Produkt — sie heissen dort verschieden.
func PruefeToken(token, pubkeyPEM, produkt string, jetzt time.Time) TokenUrteil {
	if strings.TrimSpace(token) == "" {
		return TokenUrteil{false, "fehlt", map[string]any{}}
	}
	nutzlast, err := pruefeSignatur(token, pubkeyPEM)
	if err != nil {
		return TokenUrteil{false, "ungueltig", map[string]any{}}
	}
	// nil/fehlend wird geduldet: Tokens aus der Zeit vor der Console trugen das
	// Feld nicht. Ein FALSCHES Produkt wird abgewiesen — darum geht es.
	if p, da := nutzlast["product"]; da && p != nil {
		if s, ok := p.(string); !ok || s != produkt {
			return TokenUrteil{false, "falsches_produkt", nutzlast}
		}
	}
	if s, ok := nutzlast["expires_at"].(string); ok {
		if ablauf, gut := ZeitLesen(s); gut && jetzt.After(ablauf) {
			return TokenUrteil{false, "abgelaufen", nutzlast}
		}
	}
	return TokenUrteil{true, "ok", nutzlast}
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

	if roh == nil {
		return ManifestUrteil{Status: "unbekannt", Detail: "unerreichbar"}
	}
	m, err := pruefeSignatur(*roh, pubkeyPEM)
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
