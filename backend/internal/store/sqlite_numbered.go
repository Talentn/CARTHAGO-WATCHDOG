package store

import (
	"database/sql"
	"fmt"
	"time"

	"carthago/backend/migrations"
)

// migrateNumbered applies the migrations in migrations.SQLiteNumbered that the database has
// not recorded yet. See migrations.Numbered for why these are tracked by number.
func migrateNumbered(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (number INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_ms BIGINT NOT NULL)`); err != nil {
		return err
	}
	known := map[int]bool{}
	for i, m := range migrations.SQLiteNumbered {
		if known[m.Number] || i > 0 && m.Number < migrations.SQLiteNumbered[i-1].Number {
			return fmt.Errorf("numbered migrations must be unique and ascending: %04d_%s", m.Number, m.Name)
		}
		known[m.Number] = true
	}
	applied := map[int]bool{}
	rows, err := db.Query(`SELECT number, name FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n int
		var name string
		if err := rows.Scan(&n, &name); err != nil {
			rows.Close()
			return err
		}
		// As with user_version: a migration this gateway does not know means a newer gateway
		// wrote the database.
		if !known[n] {
			rows.Close()
			return fmt.Errorf("database has migration %04d_%s, which is newer than this gateway understands; upgrade the gateway or restore a matching database", n, name)
		}
		applied[n] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, m := range migrations.SQLiteNumbered {
		if applied[m.Number] {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %04d_%s: %w", m.Number, m.Name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (number, name, applied_ms) VALUES (?, ?, ?)`, m.Number, m.Name, time.Now().UnixMilli()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
