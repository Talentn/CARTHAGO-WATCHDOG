package store

import (
	"database/sql"
	"fmt"
	"time"

	"carthago/backend/migrations"
)

const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (number INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_ms BIGINT NOT NULL)`

// adoptPositioned takes over a database whose user_version v is past the closed
// position-based list because a branch's gateway applied, by position, a migration that
// has a number here (migrations.Numbered.Position). Each such migration is recorded under
// its number and user_version is lowered again, so the database opens with this gateway
// and still opens with a gateway that only knows the closed list. It returns the
// user_version that remains; a version it cannot account for is left as it is, and the
// caller refuses the database.
//
// A migration already recorded under its number was applied by this gateway, so it is not
// what raised user_version: two branches may have used the same position, and the tables of
// one say nothing about the other.
func adoptPositioned(db *sql.DB, v int) (int, error) {
	hasTable := func(name string) (bool, error) {
		var n int
		err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
		return n > 0, err
	}
	recorded := func(number int) (bool, error) {
		if ok, err := hasTable("schema_migrations"); err != nil || !ok {
			return false, err
		}
		var n int
		err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE number = ?`, number).Scan(&n)
		return n > 0, err
	}
	for v > len(migrations.SQLite) {
		var found *migrations.Numbered
		for i := range migrations.SQLiteNumbered {
			m := &migrations.SQLiteNumbered[i]
			if m.Position != v || m.Probe == "" {
				continue
			}
			if done, err := recorded(m.Number); err != nil {
				return v, err
			} else if done {
				continue
			}
			if ok, err := hasTable(m.Probe); err != nil {
				return v, err
			} else if ok {
				found = m
				break
			}
		}
		if found == nil {
			return v, nil
		}
		tx, err := db.Begin()
		if err != nil {
			return v, err
		}
		for _, q := range []string{
			createSchemaMigrations,
			fmt.Sprintf(`INSERT OR IGNORE INTO schema_migrations (number, name, applied_ms) VALUES (%d, '%s', %d)`, found.Number, found.Name, time.Now().UnixMilli()),
			fmt.Sprintf(`PRAGMA user_version = %d`, v-1),
		} {
			if _, err := tx.Exec(q); err != nil {
				tx.Rollback()
				return v, fmt.Errorf("taking over migration %04d_%s: %w", found.Number, found.Name, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return v, err
		}
		v--
	}
	return v, nil
}

// migrateNumbered applies the migrations in migrations.SQLiteNumbered that the database has
// not recorded yet. See migrations.Numbered for why these are tracked by number.
func migrateNumbered(db *sql.DB) error {
	if _, err := db.Exec(createSchemaMigrations); err != nil {
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
