#!/bin/bash
# pruefstand/laeufer.sh [bauart …]
#
# Faehrt jede Bauart ueber DIESELBEN Faelle und vergleicht das Urteil.
# Ohne Argument laufen alle vorhandenen; sonst nur die genannten (py|js|go).
#
# DER PUNKT IST NICHT, DASS JEDE BAUART TESTS HAT. Der Punkt ist, dass sie
# dieselbe Antwort geben. Drei eigene Testreihen koennten dreimal gruen sein und
# dreierlei bedeuten — genau das ist mit den sechs handgeschriebenen Umsetzungen
# passiert, aus denen dieses Paket entstanden ist.
#
# Weicht eine Bauart ab, ist SIE rot — nicht der Fall. Die Faelle sind aus dem
# heutigen Verhalten der Referenz abgeleitet (jarvis-email-dashboard); wo die
# REFERENZ abweicht, ist erst zu entscheiden, wer recht hat.
set -uo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WURZEL="$(dirname "$HIER")"
FAELLE="$HIER/faelle"

PY="${JARVIS_LIZENZ_PY:-python3}"

# `bauart_ruf <bauart>` — liest den Fall auf stdin, gibt das Urteil auf stdout.
bauart_ruf() {
  case "$1" in
    py) "$PY" "$WURZEL/paket/py/pruefling.py" ;;
    js) node "$WURZEL/paket/js/pruefling.mjs" ;;
    go) "$WURZEL/paket/go/pruefling/pruefling" ;;
    *)  echo "unbekannte Bauart: $1" >&2; return 2 ;;
  esac
}

bauart_da() {
  case "$1" in
    py) [ -f "$WURZEL/paket/py/pruefling.py" ] ;;
    js) [ -f "$WURZEL/paket/js/pruefling.mjs" ] && command -v node >/dev/null ;;
    go) [ -x "$WURZEL/paket/go/pruefling/pruefling" ] ;;
  esac
}

# Urteile vergleichen sich nur, wenn sie kanonisch sind: sortierte Schluessel,
# feste Trenner. Sonst waere ein Unterschied in der Reihenfolge ein Befund.
kanonisch() {
  "$PY" -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception as e: print('UNLESBAR:', e); raise SystemExit(0)
print(json.dumps(d, sort_keys=True, separators=(',',':'), ensure_ascii=False))"
}

BAUARTEN=("$@")
if [ ${#BAUARTEN[@]} -eq 0 ]; then BAUARTEN=(py js go); fi

# Der Go-Prüfling ist ein lokal gebautes, von git ignoriertes Erzeugnis. Ein alter
# Build misst den alten Kern, ohne dass es jemand merkt (10.11.2026: nach Kern 0.2.2
# liess der Build vom 31.10. zwei type-Fälle als gültige Tokens durch). Darum vor
# jedem Lauf neu bauen; go build ist inkrementell. Scheitert der Build, ist Go
# nicht messbar — kein Rückfall auf den alten Build.
for b in "${BAUARTEN[@]}"; do
  if [ "$b" = go ] && command -v go >/dev/null && [ -d "$WURZEL/paket/go/pruefling" ]; then
    (cd "$WURZEL/paket/go" && go build -o pruefling/pruefling ./pruefling) \
      || { echo "FEHLER: Go-Prüfling lässt sich nicht bauen — nicht messbar"; exit 2; }
  fi
done

VORHANDEN=()
for b in "${BAUARTEN[@]}"; do
  if bauart_da "$b"; then VORHANDEN+=("$b"); else echo "übersprungen: $b (nicht gebaut)"; fi
done
[ ${#VORHANDEN[@]} -gt 0 ] || { echo "FEHLER: keine einzige Bauart vorhanden"; exit 2; }

shopt -s nullglob
DATEIEN=("$FAELLE"/*.json)
shopt -u nullglob
[ ${#DATEIEN[@]} -gt 0 ] || { echo "FEHLER: keine Fälle in $FAELLE"; exit 2; }

echo "Prüfstand jarvis-lizenz — ${#DATEIEN[@]} Fälle × ${#VORHANDEN[@]} Bauarten (${VORHANDEN[*]})"
echo

BESTANDEN=0; GEFALLEN=0
for datei in "${DATEIEN[@]}"; do
  name=$(basename "$datei" .json)
  soll=$("$PY" -c "
import json,sys
print(json.dumps(json.load(open('$datei'))['erwartet'], sort_keys=True, separators=(',',':'), ensure_ascii=False))")
  eingang=$("$PY" -c "
import json
print(json.dumps(json.load(open('$datei'))['eingang'], ensure_ascii=False))")

  fehler=""
  for b in "${VORHANDEN[@]}"; do
    ist=$(printf '%s' "$eingang" | bauart_ruf "$b" 2>&1 | kanonisch)
    [ "$ist" = "$soll" ] || fehler="$fehler
      [$b] $ist"
  done

  if [ -z "$fehler" ]; then
    BESTANDEN=$((BESTANDEN + 1)); printf '  \033[32m✓\033[0m %s\n' "$name"
  else
    GEFALLEN=$((GEFALLEN + 1)); printf '  \033[31m✗\033[0m %s\n' "$name"
    echo "      soll  $soll"
    printf '%s\n' "$fehler"
  fi
done

echo
echo "───────────────────────────────────────────"
if [ "$GEFALLEN" -eq 0 ]; then
  printf '\033[32m%d Fälle, alle Bauarten einig\033[0m\n' "$BESTANDEN"; exit 0
fi
printf '\033[31m%d bestanden, %d GEFALLEN\033[0m\n' "$BESTANDEN" "$GEFALLEN"; exit 1
