// Package migrations embeds the gateway schema.
package migrations

import _ "embed"

//go:embed sqlite/0001_init.sql
var SQLiteInit string

//go:embed sqlite/0002_detections.sql
var SQLiteDetections string

// SQLite lists every migration in order. Each is idempotent (IF NOT EXISTS), so they are all
// applied on every open.
var SQLite = []string{SQLiteInit, SQLiteDetections}
