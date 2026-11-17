package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestMapOutlineStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, b := range backends(t) {
		st := b.(MapOutlineStore)
		t.Run(name, func(t *testing.T) {
			lines := &MapOutline{TenantID: "t1", MapID: "de_test", Kind: OutlineLines, Lines: `[[0,0,100,0]]`, Segments: 1, Rect: [4]int32{0, 0, 100, 0}, UpdatedBy: "ada", UpdatedAt: now}
			pic := &MapOutline{TenantID: "t1", MapID: "a map/with spaces", Kind: OutlineImage, PNG: []byte{1, 2, 3}, Width: 4, Height: 2, Rect: [4]int32{-5, -6, 7, 8}, UpdatedBy: "game server", UpdatedAt: now}
			rival := &MapOutline{TenantID: "t2", MapID: "de_test", Kind: OutlineLines, Lines: `[[9,9,8,8]]`, Segments: 1, UpdatedAt: now}
			for _, o := range []*MapOutline{lines, pic, rival} {
				if err := st.PutMapOutline(ctx, o); err != nil {
					t.Fatal(err)
				}
			}
			got, err := st.GetMapOutline(ctx, "t1", "de_test")
			if err != nil || got.Kind != OutlineLines || got.Lines != `[[0,0,100,0]]` || got.Segments != 1 || got.Rect != lines.Rect || got.UpdatedBy != "ada" || !got.UpdatedAt.Equal(now) || len(got.PNG) != 0 {
				t.Fatalf("lines read back: %+v %v", got, err)
			}
			got, err = st.GetMapOutline(ctx, "t1", "a map/with spaces")
			if err != nil || got.Kind != OutlineImage || !bytes.Equal(got.PNG, []byte{1, 2, 3}) || got.Width != 4 || got.Height != 2 || got.Rect != pic.Rect {
				t.Fatalf("picture read back: %+v %v", got, err)
			}
			// One outline per studio and map: each studio reads its own.
			if got, err := st.GetMapOutline(ctx, "t2", "de_test"); err != nil || got.Lines != `[[9,9,8,8]]` {
				t.Fatalf("the other studio's outline: %+v %v", got, err)
			}
			if _, err := st.GetMapOutline(ctx, "t2", "a map/with spaces"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio reads the picture: %v", err)
			}
			list, err := st.ListMapOutlines(ctx, "t1")
			if err != nil || len(list) != 2 || list[0].MapID != "a map/with spaces" || list[1].MapID != "de_test" || list[0].PNG != nil || list[1].Lines != "" || list[1].Segments != 1 {
				t.Fatalf("list: %+v %v", list, err)
			}
			// A second upload replaces the first, also with the other kind.
			lines.Kind, lines.Lines, lines.Segments, lines.PNG, lines.Width, lines.Height = OutlineImage, "", 0, []byte{9}, 1, 1
			if err := st.PutMapOutline(ctx, lines); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.GetMapOutline(ctx, "t1", "de_test"); got.Kind != OutlineImage || got.Lines != "" || got.Segments != 0 || !bytes.Equal(got.PNG, []byte{9}) {
				t.Fatalf("replaced: %+v", got)
			}
			if list, _ := st.ListMapOutlines(ctx, "t1"); len(list) != 2 {
				t.Fatalf("after replacing: %d outlines", len(list))
			}
			if err := st.DeleteMapOutline(ctx, "t2", "a map/with spaces"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio removes the picture: %v", err)
			}
			if err := st.DeleteMapOutline(ctx, "t1", "de_test"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetMapOutline(ctx, "t1", "de_test"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("removed: %v", err)
			}
			if _, err := st.GetMapOutline(ctx, "t2", "de_test"); err != nil {
				t.Fatalf("removing t1's outline removed t2's: %v", err)
			}
		})
	}
}
