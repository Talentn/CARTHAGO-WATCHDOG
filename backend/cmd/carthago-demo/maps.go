package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/sim/localgw"
)

// registerMap is the studio's game server registering the outline of the demo's map for
// the match replay: POST /v1/maps under its server key, with the map's walls as lines.
func (s *story) registerMap() (int, error) {
	lines := synth.YardWallLines()
	raw, err := json.Marshal(map[string]any{"map": synth.YardID, "lines": lines})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(s.ctx, "POST", s.gw.API+"/v1/maps", bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+localgw.ServerKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("POST /v1/maps: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return len(lines), nil
}
