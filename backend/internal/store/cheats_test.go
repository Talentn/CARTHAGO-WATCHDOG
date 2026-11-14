package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKnownCheats(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]CheatStore{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		h1, h2 := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
		c := &KnownCheat{TenantID: "t1", SHA256: h1, Name: "Wall", Note: "from a report", AddedBy: "ada", AddedAt: time.UnixMilli(1_700_000_000_000).UTC()}
		if err := st.AddKnownCheat(ctx, c); err != nil || c.ID == 0 {
			t.Fatalf("%s: add: %v id %d", name, err, c.ID)
		}
		if err := st.AddKnownCheat(ctx, &KnownCheat{TenantID: "t1", SHA256: h1, Name: "again", AddedBy: "ada"}); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("%s: the same hash twice: %v", name, err)
		}
		if err := st.AddKnownCheat(ctx, &KnownCheat{TenantID: "t1", SHA256: h2, Name: "Aim", AddedBy: "ada"}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := st.KnownCheat(ctx, "t1", h1)
		if err != nil || got.Name != "Wall" || got.Note != "from a report" || got.AddedBy != "ada" || !got.AddedAt.Equal(c.AddedAt) {
			t.Fatalf("%s: lookup: %+v %v", name, got, err)
		}
		// The list belongs to one studio.
		if _, err := st.KnownCheat(ctx, "t2", h1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: another studio's list matched: %v", name, err)
		}
		list, err := st.ListKnownCheats(ctx, "t1")
		if err != nil || len(list) != 2 || list[0].Name != "Aim" {
			t.Fatalf("%s: list: %+v %v", name, list, err)
		}
		if _, err := st.RemoveKnownCheat(ctx, "t2", c.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: removed across studios: %v", name, err)
		}
		if gone, err := st.RemoveKnownCheat(ctx, "t1", c.ID); err != nil || gone.SHA256 != h1 {
			t.Fatalf("%s: remove: %+v %v", name, gone, err)
		}
		if _, err := st.KnownCheat(ctx, "t1", h1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: still listed after removal: %v", name, err)
		}
	}
	if _, ok := CleanSHA256(" " + strings.Repeat("AB", 32) + "\n"); !ok {
		t.Fatal("an upper-case hash with spaces around it is a hash")
	}
	if _, ok := CleanSHA256("abcd"); ok {
		t.Fatal("a short string is not a hash")
	}
}
