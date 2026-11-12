// Package migrations embeds the gateway schema.
package migrations

import _ "embed"

//go:embed sqlite/0001_init.sql
var SQLiteInit string

//go:embed sqlite/0002_ek_chain.sql
var sqliteEKChain string

//go:embed sqlite/0003_detections.sql
var sqliteDetections string

//go:embed sqlite/0004_telemetry_v2.sql
var sqliteTelemetryV2 string

//go:embed sqlite/0005_bot_evidence.sql
var sqliteBotEvidence string

// SQLite lists the migrations in order; migration i+1 sets PRAGMA user_version = i+1.
var SQLite = []string{SQLiteInit, sqliteEKChain, sqliteDetections, sqliteTelemetryV2, sqliteBotEvidence}
