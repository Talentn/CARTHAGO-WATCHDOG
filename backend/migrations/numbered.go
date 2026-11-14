package migrations

import _ "embed"

// Numbered is a migration that is tracked by its number in the schema_migrations table,
// not by its position in a list.
//
// The migrations in SQLite (0001 to 0019) are applied by position and recorded in PRAGMA
// user_version, so two branches that each append "the next one" give the same version to
// different schemas. From 0020 on a migration is recorded by number: branches can add
// migrations independently as long as their numbers differ, and a database applies
// whichever it has not seen yet, in ascending order.
type Numbered struct {
	Number int
	Name   string
	SQL    string
	// Position and Probe describe a migration that a branch first added to the
	// position-based list, before it was given a number here: Position is the user_version
	// that branch's gateway left behind, and Probe is a table that exists only where the
	// migration ran. A database that reports Position and has the Probe table is taken over
	// as it is: the migration is recorded under its number and user_version goes back to
	// the end of the closed list. Zero and empty for a migration that was always numbered.
	Position int
	Probe    string
}

//go:embed sqlite/0020_dashboard_auth.sql
var sqliteDashboardAuth string

//go:embed sqlite/0021_oracle.sql
var sqliteOracle string

//go:embed sqlite/0022_bans.sql
var sqliteBans string

//go:embed sqlite/0023_known_cheats.sql
var sqliteKnownCheats string

//go:embed sqlite/0024_economy.sql
var sqliteEconomy string

// SQLiteNumbered lists the numbered migrations in ascending order. They run after every
// migration in SQLite.
var SQLiteNumbered = []Numbered{
	{Number: 20, Name: "dashboard_auth", SQL: sqliteDashboardAuth},
	// Was 0006 by position on the ai-engine branch.
	{Number: 21, Name: "oracle", SQL: sqliteOracle, Position: 6, Probe: "oracle_scores"},
	{Number: 22, Name: "bans", SQL: sqliteBans},
	{Number: 23, Name: "known_cheats", SQL: sqliteKnownCheats},
	{Number: 24, Name: "economy", SQL: sqliteEconomy},
}
