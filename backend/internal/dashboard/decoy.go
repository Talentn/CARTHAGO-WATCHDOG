package dashboard

import (
	"encoding/json"

	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/store"
)

// decoyView is a decoy_reaction evidence's explanation laid out for the page. The replay's
// target is the decoy's track.
type decoyView struct {
	Slot uint32
	knowledge.Explanation
	SVG *replaySVG
}

func parseDecoy(e *store.Evidence) *decoyView {
	if e == nil || e.Rule != "decoy_reaction" || e.Raw == "" {
		return nil
	}
	var v decoyView
	if err := json.Unmarshal([]byte(e.Raw), &struct {
		Slot *uint32 `json:"slot"`
		*knowledge.Explanation
	}{&v.Slot, &v.Explanation}); err != nil || v.Decoys == nil {
		return nil
	}
	if r := v.Replay; r != nil {
		v.SVG = layoutReplay(r)
	}
	return &v
}

func decoysOf(evs []store.Evidence) []*decoyView {
	var out []*decoyView
	for i := range evs {
		if v := parseDecoy(&evs[i]); v != nil {
			out = append(out, v)
		}
	}
	return out
}
