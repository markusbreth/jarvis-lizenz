#!/bin/bash
# pruefstand/baue-release.sh <version>
#
# Baut die beiden Artefakte einer Version und druckt die Zeilen, die ein Produkt
# in seine Abhaengigkeiten schreibt — mit Hash.
#
# WARUM UEBER EIN SKRIPT: die Artefakte tragen Hashes, und ein Hash, den jemand
# von Hand abschreibt, ist beim naechsten Mal falsch. Erzeugt heisst
# reproduzierbar — dieselbe Ueberlegung wie bei `erzeuge-faelle.py`.
#
# WARUM RELEASE-ANHAENGE UND KEIN REGISTRY (Entscheidung vom 28.08.2026):
# das E-Mail-Produkt baut sein Image mit `pip install --require-hashes`, und
# eine Git-Abhaengigkeit hat dort keinen Hash; npm kann Unterverzeichnisse eines
# Repos ohnehin nicht. Ein Release-Anhang loest beides ohne ein neues Konto und
# ohne ein Token, das gepflegt und gesichert werden muesste. Gemessen: pip nimmt
# ein gehashtes sdist unter `--require-hashes` an, npm installiert aus einer
# Tarball-URL.
#
# ACHTUNG, DER GRUND FUER DEN ANHANG STATT DES AUTO-ARCHIVS: GitHubs
# automatisch erzeugte `archive/`-Tarballs sind NICHT byte-stabil (die
# Kompression hat sich in der Vergangenheit geaendert). Ein hochgeladener Anhang
# ist es. Ein wandernder Hash waere ein Fehlschlag ohne Ursache.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "Aufruf: $0 <version>   (z. B. v0.1.0)"; exit 2; }

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WURZEL="$(dirname "$HIER")"
AUS="$WURZEL/.release"
rm -rf "$AUS"; mkdir -p "$AUS"

echo "── Python-sdist"
BAU=$(mktemp -d)
python3 -m venv "$BAU/v" >/dev/null
"$BAU/v/bin/pip" -q install build
"$BAU/v/bin/python" -m build --sdist --outdir "$AUS" "$WURZEL/paket/py" >/dev/null
rm -rf "$BAU"
SDIST=$(ls "$AUS"/*.tar.gz)

echo "── npm-Tarball"
( cd "$WURZEL/paket/js" && npm pack --silent --pack-destination "$AUS" >/dev/null )
NPM=$(ls "$AUS"/*.tgz | grep -v "$(basename "$SDIST")")

SHA_PY=$(shasum -a 256 "$SDIST" | cut -d' ' -f1)
SHA_JS=$(shasum -a 256 "$NPM"   | cut -d' ' -f1)
BASIS="https://github.com/markusbreth/jarvis-lizenz/releases/download/$VERSION"

cat > "$AUS/EINBINDEN.md" <<EOF
# jarvis-lizenz $VERSION einbinden

## Python (\`requirements.lock\`, auch unter \`--require-hashes\`)

\`\`\`
jarvis-lizenz @ $BASIS/$(basename "$SDIST") \\
    --hash=sha256:$SHA_PY
\`\`\`

## Node (\`package.json\`)

\`\`\`json
"@markusbreth/jarvis-lizenz": "$BASIS/$(basename "$NPM")"
\`\`\`

Hash zum Nachprüfen: \`sha256:$SHA_JS\`

## Go

\`\`\`
go get github.com/markusbreth/jarvis-lizenz/paket/go@$VERSION
\`\`\`

Go braucht keinen Anhang — der Modul-Proxy zieht direkt aus dem öffentlichen
Repo und prüft selbst gegen \`go.sum\`.
EOF

echo
echo "Artefakte in $AUS:"
ls -1 "$AUS" | sed 's/^/  /'
echo
cat "$AUS/EINBINDEN.md"
