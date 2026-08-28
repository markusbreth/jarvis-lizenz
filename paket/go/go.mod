// Der Modulpfad MUSS Repo-Pfad + Unterverzeichnis sein, sonst findet `go get`
// das Paket nicht. Erst stand hier `.../jarvis-lizenz/go` — der Ordner heisst
// aber `paket/go`, und ein Verbraucher waere beim Holen ins Leere gelaufen.
// Lokal gebaut haette man das nie gemerkt.
module github.com/markusbreth/jarvis-lizenz/paket/go

go 1.22
