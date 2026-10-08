package inspectionlive

import (
	"crypto/sha256"
	"encoding/hex"
)

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
