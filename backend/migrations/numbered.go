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
}

//go:embed sqlite/0020_dashboard_auth.sql
var sqliteDashboardAuth string

// SQLiteNumbered lists the numbered migrations in ascending order. They run after every
// migration in SQLite.
var SQLiteNumbered = []Numbered{
	{Number: 20, Name: "dashboard_auth", SQL: sqliteDashboardAuth},
}
