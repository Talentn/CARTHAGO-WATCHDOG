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

// Who loaded which file comes out of the stored module evidence the same way from both
// stores, and the proposal threshold, dismissals and ban labels are kept per studio.
func TestModuleSightingsAndProposalSettings(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	type both interface {
		CheatStore
		OracleStore
		AddEvidence(ctx context.Context, evs []Evidence) error
	}
	for name, st := range map[string]both{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		h1, h2 := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
		at := time.UnixMilli(1_700_000_000_000).UTC()
		raw := func(code, b, module, sum string) string {
			return `{"code":"` + code + `","a":"0x7ff000","b":"` + b + `","detail":"` + module + `","sha256":"` + sum + `"}`
		}
		ev := func(player, session, raw string, at time.Time) Evidence {
			return Evidence{TenantID: "t1", PlayerHash: player, SessionID: session, Source: SourceClient, Rule: "module", Summary: "module", Raw: raw, ObservedAt: at}
		}
		if err := st.AddEvidence(ctx, []Evidence{
			// Not signed (2), outside the game folder (class 0), with flags and seconds above.
			ev("max", "s1", raw("FINDING_CODE_MODULE_SIGNATURE", "0x1200010002", "wall.dll", h1), at),
			ev("max", "s2", raw("FINDING_CODE_MODULE_SIGNATURE", "0x900020002", "wall.dll", h1), at.Add(time.Hour)),
			ev("nia", "s3", raw("FINDING_CODE_MODULE_SIGNATURE", "0x2", "renamed.dll", h1), at),
			// Signed and valid (1), in the game folder (class 1).
			ev("max", "s1", raw("FINDING_CODE_MODULE_SIGNATURE", "0x10101", "steam_api.dll", h2), at),
			// Not module evidence, not JSON, and no hash.
			ev("max", "s1", raw("FINDING_CODE_EXTERNAL_HANDLE", "0x2", "tool.exe", h2), at),
			ev("max", "s1", `not json "sha256"`, at),
			ev("max", "s1", `{"code":"FINDING_CODE_MODULE_SIGNATURE","b":"0x2","detail":"nohash.dll"}`, at),
			{TenantID: "t2", PlayerHash: "zed", SessionID: "s9", Source: SourceClient, Rule: "module", Raw: raw("FINDING_CODE_MODULE_SIGNATURE", "0x2", "other.dll", h2), ObservedAt: at},
		}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := st.ListModuleSightings(ctx, "t1")
		if err != nil || len(got) != 3 {
			t.Fatalf("%s: sightings: %+v %v", name, got, err)
		}
		by := map[string]ModuleSighting{}
		for _, s := range got {
			by[s.PlayerHash+"/"+s.Module] = s
		}
		if s := by["max/wall.dll"]; s.SHA256 != h1 || s.Sessions != 2 || s.Signature != 2 || s.PathClass != 0 || !s.LastSeen.Equal(at.Add(time.Hour)) {
			t.Errorf("%s: max's wall.dll: %+v", name, s)
		}
		if s := by["nia/renamed.dll"]; s.SHA256 != h1 || s.Sessions != 1 || s.Signature != 2 {
			t.Errorf("%s: nia's renamed.dll: %+v", name, s)
		}
		if s := by["max/steam_api.dll"]; s.SHA256 != h2 || s.Signature != 1 || s.PathClass != 1 {
			t.Errorf("%s: max's steam_api.dll: %+v", name, s)
		}

		if n, err := st.CheatProposalAccounts(ctx, "t1"); err != nil || n != DefaultProposalAccounts {
			t.Fatalf("%s: default threshold: %d %v", name, n, err)
		}
		if err := st.SetCheatProposalAccounts(ctx, "t1", 1); err != nil {
			t.Fatal(err)
		}
		n1, _ := st.CheatProposalAccounts(ctx, "t1")
		n2, _ := st.CheatProposalAccounts(ctx, "t2")
		if n1 != 1 || n2 != DefaultProposalAccounts {
			t.Fatalf("%s: thresholds: %d and %d", name, n1, n2)
		}
		for range 2 {
			if err := st.DismissCheatProposal(ctx, "t1", h1, "rev", at); err != nil {
				t.Fatalf("%s: dismiss: %v", name, err)
			}
		}
		d1, _ := st.DismissedCheatProposals(ctx, "t1")
		d2, _ := st.DismissedCheatProposals(ctx, "t2")
		if !d1[h1] || len(d1) != 1 || len(d2) != 0 {
			t.Fatalf("%s: dismissals: %v and %v", name, d1, d2)
		}

		l := &SessionLabel{TenantID: "t1", SessionID: "s1", PlayerHash: "max", Label: LabelConfirmedCheat, Reviewer: "ban CW-1", LabelledAt: at, Source: LabelSourceBan, BanRef: "CW-1"}
		if err := st.SetSessionLabel(ctx, l, LabelSet, ""); err != nil {
			t.Fatal(err)
		}
		if got, err := st.GetSessionLabel(ctx, "t1", "s1"); err != nil || got.Source != LabelSourceBan || got.BanRef != "CW-1" {
			t.Fatalf("%s: ban label: %+v %v", name, got, err)
		}
		// A reviewer's label replaces a ban's and is the reviewer's from then on.
		l.Source, l.BanRef, l.Reviewer = "", "", "rev"
		if err := st.SetSessionLabel(ctx, l, LabelSet, ""); err != nil {
			t.Fatal(err)
		}
		if list, err := st.ListSessionLabels(ctx, "t1", OracleFilter{PlayerHash: "max"}); err != nil || len(list) != 1 || list[0].Source != "" || list[0].BanRef != "" {
			t.Fatalf("%s: labels: %+v %v", name, list, err)
		}
	}
}
