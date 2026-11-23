module github.com/lidessen/keyref/server

go 1.26.0

require (
	github.com/lidessen/keyref/proto v0.0.0 // replaced by ../proto
	modernc.org/sqlite v1.61.0
)

require golang.org/x/crypto v0.54.0

require github.com/coder/websocket v1.8.12 // indirect

require (
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tursodatabase/libsql-client-go v0.0.0-20260528064733-9d5d30a29a60
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace github.com/lidessen/keyref/proto => ../proto
