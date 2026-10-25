// Package qr renders terminal QR codes with the skip2/go-qrcode
// half-block output (docs/protocol.md §2.3, §4).
package qr

import (
	"fmt"
	"io"

	qrcode "github.com/skip2/go-qrcode"
)

// Print writes the payload as a scannable QR code using Unicode
// half-block characters, followed by a blank line.
func Print(w io.Writer, payload string) error {
	code, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("qr: %w", err)
	}
	_, err = fmt.Fprint(w, code.ToSmallString(false), "\n")
	return err
}
