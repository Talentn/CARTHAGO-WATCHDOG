package main

import "carthago/backend/internal/oracle"

// defaultLocalModel is the analyst model a new bundle names: the one the fetch script
// downloads. See docs/oracle.md for how it was chosen.
var defaultLocalModel = oracle.LocalModelRef{ContextTokens: 4096}
