// Package migrations embeds the gateway schema.
package migrations

import _ "embed"

//go:embed sqlite/0001_init.sql
var SQLiteInit string
