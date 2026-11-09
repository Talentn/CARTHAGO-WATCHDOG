// Command gen-testvectors writes the golden vectors in proto/testvectors/. Rerun it only on
// an intentional wire-format change; both the Go and Rust test suites check the files.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"sentinel/backend/internal/protocol"
)

func main() {
	out := flag.String("out", "../proto/testvectors", "output directory")
	flag.Parse()
	tok, err := protocol.BuildTokenVectors()
	must(err)
	hs, err := protocol.BuildHandshakeVectors()
	must(err)
	if old, err := os.ReadFile(filepath.Join(*out, "handshake.json")); err == nil {
		// Keep the existing verify-only ECDSA signature so regeneration is a no-op diff.
		var prev protocol.HandshakeVectors
		if json.Unmarshal(old, &prev) == nil && len(prev.P256.SignatureRS) == 64 && string(prev.ProveDigest) == string(hs.ProveDigest) {
			hs.P256 = prev.P256
		}
	}
	aead, err := protocol.BuildAEADVectors()
	must(err)
	must(os.MkdirAll(*out, 0o755))
	write(*out, "token.json", tok)
	write(*out, "handshake.json", hs)
	write(*out, "aead.json", aead)
}

func write(dir, name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644))
	log.Printf("wrote %s", filepath.Join(dir, name))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
