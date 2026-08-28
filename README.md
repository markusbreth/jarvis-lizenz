# jarvis-lizenz

Der geteilte Kern der Lizenzprüfung — **eine** Antwort in drei Sprachen.

```
paket/py/    jarvis_lizenz          (Python)
paket/js/    @markusbreth/jarvis-lizenz  (Node ≥ 20, ESM)
paket/go/    github.com/markusbreth/jarvis-lizenz/paket/go/lizenz
pruefstand/  faelle/*.json  ·  laeufer.sh  ·  anker-referenz.py
VERTRAG.md   was der Kern entscheidet — und was ausdrücklich nicht
```

## Warum

Am 28.08.2026 gemessen: **sechs Produkte, sechs eigene Umsetzungen derselben
Sache.** Die Köpfe sagen es selbst — *„Port des bewährten Musters aus
jarvis-email-dashboard"*, *„Copied (not imported)"*. Die Kopien sind
auseinandergedriftet, und ob die drei Härtungen in allen sechs stehen, wusste
niemand.

## Was drin ist

Eine **reine Zustandsmaschine**: keine Netzaufrufe, keine Datenbank, keine Uhr.
Alles Veränderliche kommt als Argument herein.

| | |
|---|---|
| `pruefe_token` | Signatur · Produkt · Ablauf |
| `bewerte_manifest` | Typ · Frische · Rückroll-Sperre · Widerruf |
| `naechster_zustand` | die Einbahnstraßen: klebender Widerruf, stabiler Karenz-Anker |
| `sperrgrund` | `null` · `widerrufen` · `pruefung_ueberfaellig` |

Was **nicht** drin ist: was bei „ungültig" passiert. 403 gegen Nur-Lese gegen
Weiterleitung, welche Pfade frei bleiben, ob GET durchgeht — das bleibt beim
Produkt, und die Unterschiede sind teilweise Absicht (GoBD: *der Kunde kommt an
seine eigenen Bücher*). Siehe [VERTRAG.md](VERTRAG.md).

## Prüfen

```bash
pruefstand/laeufer.sh            # alle Bauarten über dieselben Fälle
pruefstand/laeufer.sh py js      # nur bestimmte
python3 pruefstand/erzeuge-faelle.py   # Fälle neu erzeugen (echte Signaturen)
```

**Der Punkt ist nicht, dass jede Bauart Tests hat — sondern dass sie dieselbe
Antwort geben.** Drei eigene Testreihen könnten dreimal grün sein und dreierlei
bedeuten; genau das ist mit den sechs handgeschriebenen Umsetzungen passiert.

Weicht eine Bauart ab, ist **sie** rot — nicht der Fall.

## Woher die Fälle kommen

Sie sind aus dem heutigen Verhalten der Referenz (`jarvis-email-dashboard`)
**abgeleitet**, nicht erfunden. `pruefstand/anker-referenz.py` fährt die
Token-Fälle durch die Referenz selbst und hält sie ehrlich — ohne ihn wäre nur
bewiesen, dass zwei Dinge desselben Autors zueinander passen.

Der Anker deckt die Token-Fälle. Die Manifest- und Zustandsfälle sind in der
Referenz mit Datenbank und HTTP verwoben und dort nicht ohne Umbau vergleichbar
— genau deshalb ist der Kern hier eine reine Zustandsmaschine. Was der Anker
nicht deckt, sagt er, statt es zu behaupten.

## Warum dieses Repo öffentlich ist

Der Prüfschlüssel ist ein **öffentlicher** Schlüssel, die Prüflogik keine
Geheimwissenschaft. Was schützt, ist die Ed25519-Signatur. Öffentlich zu sein
spart jedem Produkt, jeder CI und jedem Kunden-Build ein Zugangs-Token — und
Verborgenheit hätte ohnehin nichts geschützt: wer den Container hat, liest den
Code.

**Was hier NICHT liegt:** private Signierschlüssel. Die verlassen die Werkstatt
nie.
