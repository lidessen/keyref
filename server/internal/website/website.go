// Package website serves the public Keyref homepage and install URL.
package website

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed index.html site.css site.js icons.svg logo.png fonts
var assets embed.FS

var homepage = template.Must(template.ParseFS(assets, "index.html"))

const installerURL = "https://raw.githubusercontent.com/lidessen/keyref/main/scripts/install.sh"

func Register(mux *http.ServeMux, accountVault bool) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = homepage.Execute(w, accountVault)
	})
	mux.HandleFunc("GET /install.sh", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, installerURL, http.StatusFound)
	})
	for _, name := range []string{"site.css", "site.js", "icons.svg", "fonts/inter.woff2", "fonts/recursive.woff2", "fonts/ibm-plex-mono.woff2"} {
		mux.HandleFunc("GET /assets/"+name, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, assets, name)
		})
	}
	mux.HandleFunc("GET /assets/logo.png", ServeLogo)
}

// ServeLogo also supports the account vault's existing asset URL.
func ServeLogo(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, assets, "logo.png")
}
