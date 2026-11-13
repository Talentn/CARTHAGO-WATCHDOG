package main

import "carthago/backend/internal/oracle"

// defaultLocalModel is the analyst model a new bundle names: the one the fetch script
// downloads. See docs/oracle.md for how it was chosen.
//
// Keep in step with tools/carthago-oracle-fetch.sh and tools/carthago-oracle-fetch.ps1
// (a test compares them).
var defaultLocalModel = oracle.LocalModelRef{
	ID:            "qwen2.5-1.5b-instruct-q4_k_m",
	File:          "qwen2.5-1.5b-instruct-q4_k_m.gguf",
	SHA256:        "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e",
	ContextTokens: 4096,
}
