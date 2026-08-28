// Der Pruefling der Go-Bauart: ein Fall auf stdin, ein Urteil auf stdout.
//
//	echo '<fall.json>' | ./pruefling
//
// Die Schnittstelle ist absichtlich winzig und sprachneutral — sie ist das,
// woran sich die drei Bauarten messen lassen. Nicht ihre inneren Namen, nicht
// ihre Signaturen, sondern das Urteil ueber denselben Eingang.
//
// Wortgleich zu paket/py/pruefling.py und paket/js/pruefling.mjs. Alle drei sind
// bewusst dumm: alles, was hier entschieden wuerde, waere eine Entscheidung, die
// der Pruefstand nicht sieht.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/markusbreth/jarvis-lizenz/paket/go/lizenz"
)

type zustandEin struct {
	LetzterStatus    *string `json:"letzter_status"`
	LetzteOkPruefung *string `json:"letzte_ok_pruefung"`
	PendingSeit      *string `json:"pending_seit"`
	ManifestSeq      *int    `json:"manifest_seq"`
}

type fallEin struct {
	Pubkey     string      `json:"pubkey"`
	Produkt    string      `json:"produkt"`
	Jetzt      string      `json:"jetzt"`
	KarenzTage *int        `json:"karenz_tage"`
	Token      *string     `json:"token"`
	Manifest   *string     `json:"manifest"`
	Zustand    *zustandEin `json:"zustand"`
}

type zustandAus struct {
	LetzterStatus    *string `json:"letzter_status"`
	LetzteOkPruefung *string `json:"letzte_ok_pruefung"`
	PendingSeit      *string `json:"pending_seit"`
	ManifestSeq      *int    `json:"manifest_seq"`
}

type urteilAus struct {
	TokenGueltig   bool        `json:"token_gueltig"`
	TokenGrund     string      `json:"token_grund"`
	ManifestStatus *string     `json:"manifest_status"`
	ManifestDetail *string     `json:"manifest_detail"`
	Zustand        *zustandAus `json:"zustand"`
	Sperrgrund     *string     `json:"sperrgrund"`
}

// ISO mit `Z`, ohne Bruchteile — wie die Python-Bauart sie schreibt. Eine andere
// Schreibweise waere selbst ein Unterschied, und der Vergleich meldete einen
// Befund, den es nicht gibt.
func iso(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02T15:04:05Z")
	return &s
}

func zeigerZeit(s *string) *time.Time {
	if s == nil {
		return nil
	}
	if t, gut := lizenz.ZeitLesen(*s); gut {
		return &t
	}
	return nil
}

func main() {
	// Das Manifest-Feld muss von "nicht vorhanden" unterschieden werden: `null`
	// heisst "nicht erreichbar" (ein gueltiger Eingang), das FEHLEN des
	// Schluessels heisst "diesmal gar nicht geprueft". Ein einzelnes
	// Zeiger-Feld kann das nicht ausdruecken, deshalb zweimal dekodiert.
	roh, err := os.ReadFile("/dev/stdin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "FALL KAPUTT: stdin nicht lesbar:", err)
		os.Exit(2)
	}
	var frei map[string]json.RawMessage
	if err := json.Unmarshal(roh, &frei); err != nil {
		fmt.Fprintln(os.Stderr, "FALL KAPUTT: kein JSON:", err)
		os.Exit(2)
	}
	var f fallEin
	if err := json.Unmarshal(roh, &f); err != nil {
		fmt.Fprintln(os.Stderr, "FALL KAPUTT:", err)
		os.Exit(2)
	}
	_, manifestDa := frei["manifest"]

	jetzt, gut := lizenz.ZeitLesen(f.Jetzt)
	if !gut {
		fmt.Fprintln(os.Stderr, "FALL KAPUTT: 'jetzt' ist nicht lesbar")
		os.Exit(2)
	}
	tokenText := ""
	if f.Token != nil {
		tokenText = *f.Token
	}
	tok := lizenz.PruefeToken(tokenText, f.Pubkey, f.Produkt, jetzt)

	var alt *lizenz.Zustand
	if f.Zustand != nil {
		z := lizenz.Zustand{
			LetzteOkPruefung: zeigerZeit(f.Zustand.LetzteOkPruefung),
			PendingSeit:      zeigerZeit(f.Zustand.PendingSeit),
			ManifestSeq:      f.Zustand.ManifestSeq,
		}
		if f.Zustand.LetzterStatus != nil {
			z.LetzterStatus = *f.Zustand.LetzterStatus
		}
		alt = &z
	}

	var m *lizenz.ManifestUrteil
	neu := alt
	if manifestDa {
		var letzteSeq *int
		if alt != nil {
			letzteSeq = alt.ManifestSeq
		}
		u := lizenz.BewerteManifest(f.Manifest, f.Pubkey, tok.LizenzID(), jetzt, letzteSeq)
		m = &u
		basis := lizenz.Zustand{}
		if alt != nil {
			basis = *alt
		}
		n := lizenz.NaechsterZustand(basis, u, jetzt)
		neu = &n
	}

	karenz := 7
	if f.KarenzTage != nil {
		karenz = *f.KarenzTage
	}
	grund := lizenz.Sperrgrund(neu, jetzt, karenz, tok.BrauchtHeartbeat())

	aus := urteilAus{TokenGueltig: tok.Gueltig, TokenGrund: tok.Grund}
	if m != nil {
		s, d := m.Status, m.Detail
		aus.ManifestStatus, aus.ManifestDetail = &s, &d
	}
	if neu != nil {
		z := zustandAus{
			LetzteOkPruefung: iso(neu.LetzteOkPruefung),
			PendingSeit:      iso(neu.PendingSeit),
			ManifestSeq:      neu.ManifestSeq,
		}
		if neu.LetzterStatus != "" {
			s := neu.LetzterStatus
			z.LetzterStatus = &s
		}
		aus.Zustand = &z
	}
	if grund != "" {
		aus.Sperrgrund = &grund
	}

	b, _ := json.Marshal(aus)
	fmt.Println(string(b))
}
