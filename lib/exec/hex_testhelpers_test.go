package exec

import "encoding/hex"

func hexencode(s string) string {
	return hex.EncodeToString([]byte(s))
}
