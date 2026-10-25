module github.com/lidessen/keyref/tools/vectordump

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.5
	github.com/lidessen/keyref/proto v0.0.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/lidessen/keyref/proto => ../../proto
