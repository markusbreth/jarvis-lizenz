# Der Lizenzvertrag

Was ein Produkt können muss, um an die Lizenz-Console angeschlossen zu sein —
und was es ausdrücklich selbst entscheiden darf.

Dieses Repo ist **öffentlich**. Der Prüfschlüssel ist ein *öffentlicher*
Schlüssel, die Prüflogik ist keine Geheimwissenschaft: was schützt, ist die
Ed25519-Signatur, nicht die Verborgenheit. Öffentlich zu sein spart jedem
Produkt, jeder CI und jedem Kunden-Build ein Zugangs-Token.

---

## Warum es dieses Paket gibt

Am 28.08.2026 gemessen: **sechs Produkte, sechs eigene Umsetzungen derselben
Sache.** Der Kopf der BauKI-Fassung sagt es selbst — *„Port des bewährten
Musters aus jarvis-email-dashboard"*. Die Console sagt es auch:
*„Copied (not imported) so the console runs standalone."*

Die Kopien sind auseinandergedriftet. Drei Härtungen stehen nachweislich in der
Referenz (`jarvis-email-dashboard`); ob sie in allen sechs stehen, wusste
niemand. Genau das misst der Prüfstand.

---

## Der Draht

Token und Manifest tragen **dasselbe** Format — dieselbe Funktion prüft beide:

```
b64url(canonical_json) + "." + b64url(ed25519_signature)
```

`canonical_json` ist `json.dumps(payload, sort_keys=True, separators=(",",":"))`.
Signiert wird über die **rohen Nutzlast-Bytes**, verifiziert wird über die
**dekodierten** — so können Unterschiede beim Neuserialisieren nichts kaputt
machen.

### Token

| Feld | Bedeutung |
|---|---|
| `product` | Produkt-Kennung. **Fehlt sie, gilt das Token trotzdem** — Altbestand aus der Zeit vor der Console |
| `customer` | Anzeigename |
| `license_id` | Kennung, unter der widerrufen wird |
| `issued_at` · `expires_at` | ISO-8601, `expires_at: null` = unbefristet |
| `features` | Liste von Merkmalen |
| `limits` | flach in der Wurzel (z. B. `max_mailboxes`), produktabhängig |
| `require_heartbeat` | **entscheidet, ob der Fern-Widerruf überhaupt greift** |
| `license_server` | Manifest-URL |
| `ping_url` | Lebenszeichen-Ziel; gepingt wird `{ping_url}/ping` |
| `install_id` | *seit 0.2.0, optional:* bindet das Token an eine Installation (`pruefeBindung`) |
| `renew_url` | *seit 0.2.0, optional:* wo eine Installation ein neues Token holt. Der Kern liest es nicht; es steht im Token, damit der Erneuerungsweg so wenig umbiegbar ist wie `license_server` |
| `offline` | *seit 0.2.0, optional:* ausdrücklich ausgestellte Offline-Lizenz. **Nur mit lesbarem `expires_at` gültig** (`offline_ohne_ablauf`) |

`license_server` und `ping_url` stehen **im signierten Token**, nicht in der
Umgebung: sonst ließe sich der Widerruf per Konfiguration umbiegen oder
abschalten.

### Manifest

```json
{ "type": "license-manifest", "product": "…", "issued_at": "…", "valid_until": "…",
  "revoked": ["<license_id>", …],
  "licenses": { "<license_id>": {"expires_at":…, "features":[…], "limits":{…}} },
  "seq": 42 }
```

`valid_until` ist eine **Frischegrenze, kein Ablaufdatum**: ein abgelaufenes
Manifest gilt wie *nicht erreichbar*, nicht wie ungültig. Sonst könnte ein Kunde
einen alten Stand einfrieren, um einem Widerruf zu entgehen.

---

## Die drei Härtungen

Sie sind der eigentliche Inhalt dieses Pakets. Jede steht für einen Fehler, der
zahlende Kunden gekostet hätte.

**1. Der Karenz-Anker ist stabil.** Wurde noch nie erfolgreich geprüft, zählt die
Frist ab `pending_since` — nicht ab „zuletzt versucht". Sonst schiebt jeder
Fehlversuch die Frist vor sich her, und die Frist läuft nie ab.

**2. `widerrufen` klebt.** Ein `unbekannt` (Netz gekappt, Signatur kaputt) darf
einen bestätigten Widerruf **nicht** löschen. Sonst „ent-widerruft" das Ziehen
des Netzsteckers die Lizenz für die ganze Karenzzeit. Nur ein frisches `aktiv`
löscht ihn.

**3. Abwesenheit ist NICHT maßgeblich.** Ist die `license_id` in einem gültig
signierten Manifest schlicht nicht aufgeführt, gilt `unbekannt` + Karenz — nicht
`widerrufen`. Ein unvollständiges oder seitenweise ausgeliefertes Manifest darf
keinen zahlenden Kunden lahmlegen. **Nur ein ausdrücklicher `revoked[]`-Eintrag
sperrt.**

Dazu die Rückroll-Sperre: ein Manifest mit kleinerer `seq` als die zuletzt
angenommene wird verworfen (`unbekannt`), damit ein alter Stand keinen Widerruf
zurücknimmt.

---

## Seit 0.2.0: was eine Installation beim Kunden nicht abschalten können soll

Alles hier ist **zusätzlich**. Ein Produkt, das nichts davon aufruft, bekommt
von 0.2.0 dasselbe wie von 0.1 — die 25 Fälle von 0.1 stehen unverändert im
Prüfstand und sind der Beleg.

**Kunden-Modus.** `sperrgrund(…, {kundenModus, anker})` (Go: `SperrgrundKunde`)
lässt die zweite Nachsicht fallen: solange es keinen erfolgreichen Lauf gibt,
zählt die Karenz ab dem **früheren** von `pending_seit` und `anker`, dem
`issued_at` des Tokens. Ohne lesbaren Anker sperrt er sofort; eine
`letzte_ok_pruefung` in der Zukunft gilt als fehlend. Nur ab `pending_seit` zu
zählen reichte nicht (Durchsicht 27.10.): ein gelöschter Zustand plus ein
gesperrter Lizenzserver setzte `pending_seit` im nächsten Lauf auf „jetzt“ und
schenkte eine frische Karenz, beliebig oft. Ein Widerruf klebt auch hier. Was
der Kern nicht verhindern kann: wer `letzte_ok_pruefung` regelmäßig von Hand
auf „gerade eben“ setzt, verlängert die Karenz — der Zustand ist unsigniert. Der Preis: eine frische Installation mit einem Token, das älter als die
Karenz ist, ist bis zum ersten erfolgreichen Heartbeat gesperrt — ein
erneuertes Token trägt ein neues `issued_at`.

**Bindung.** `pruefeBindung(nutzlast, installId)` sagt `ungebunden` · `ok` ·
`fremd`. Kennt die Installation ihre eigene Kennung nicht, ist das `fremd`;
nur eine Zeichenkette im Token bindet (eine Zahl ist `fremd`). Was
bei `fremd` passiert, entscheidet das Produkt (melden, zählen, sperren).

**Hochwassermarke.** `wirksameZeit(uhr, marke)` rechnet nie vor der Marke, die
der Aufrufer mitbringt (etwa den spätesten Zeitstempel seiner Datenbank), und
meldet eine zurückgestellte Uhr. Der Kern bleibt ohne Uhr und ohne Datenbank.

**Offline.** `offline: true` ohne lesbaren Ablauf ist ungültig — ohne Heartbeat
und ohne Ablauf schützte nur noch der Vertrag.

**Zeitstempel sind ISO-8601 mit `Z`.** Die Console schreibt so, und nur so lesen
die drei Sprachen gleich: ein Datum ohne Zeitzone liest JavaScript als Ortszeit,
Python und Go als UTC; ein Datum ohne Uhrzeit nimmt Go gar nicht an. Das ist
Verhalten von 0.1 und bleibt (Durchsicht 27.10.2026) — wer Token oder Manifest
ausstellt, schreibt `Z`.

---

## Was der Kern NICHT entscheidet

Der Kern sagt **ob** die Lizenz trägt. Was dann passiert, bleibt beim Produkt —
und die Unterschiede sind gemessen und teilweise Absicht:

| Frage | Beispiele aus dem Bestand |
|---|---|
| Was bei „ungültig"? | Nur-Lese (Finance, E-Mail) · 403 auf alles (BauKI, Knowledge) · Weiterleitung (Hotel OS) |
| Gehen GET-Anfragen durch? | **ja** bei Finance und E-Mail — GoBD: *der Kunde kommt an seine eigenen Bücher*. Nein bei BauKI und Knowledge |
| Welche Pfade sind frei? | Anmeldung, Health, Lizenzstatus — und beim E-Mail-Produkt zusätzlich Abmelde-, Opt-in- und Zählpfade (DSGVO) |
| Ist die Durchsetzung an? | überall Vorgabe **AUS**, ausdrücklich einzuschalten |

Ein Produkt, das diese Fragen anders beantwortet als sein Nachbar, ist deshalb
nicht falsch. Ein Produkt, das den **Kern** anders beantwortet, schon.

---

## Ausdrücklich nicht Teil davon

**Manipulationsschutz.** Wer den Container hat, kann jede Prüfung entfernen —
dagegen hilft kein Obfuskator. Der Notaus schützt gegen Versehen und gegen
Ablauf, **nicht** gegen einen Kunden, der den Container aufmacht. Das ist eine
Entscheidung und kein Rückstand.

**Gemeinsame Schlüsselpaare.** Jedes Produkt behält sein eigenes. Wären sie
zusammengelegt, würde jede Lücke im Produkt-Wächter sofort scharf.

---

## Der Prüfstand

`pruefstand/faelle/*.json` sind **sprachneutral**: Eingang und erwartetes
Urteil. Jede Bauart bringt einen winzigen Läufer mit (Fall rein, Urteil raus),
`pruefstand/laeufer.sh` fährt alle über dieselben Fälle und vergleicht.

**Weicht eine Bauart ab, ist sie rot — nicht die Fälle.** Und die Fälle sind aus
dem heutigen Verhalten der Referenz *abgeleitet*, nicht erfunden: wo die
Referenz abweicht, ist erst zu entscheiden, wer recht hat.
