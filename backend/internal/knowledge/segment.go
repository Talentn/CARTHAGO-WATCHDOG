package knowledge

import (
	pb "carthago/backend/gen/carthago/v1"
)

// Threshold is one calibration segment's flag rule. A player is flagged when the combined
// score of the scored features with enough data (Stouffer: Σz/√k) reaches Z and at least one
// of them is positive with an excess alignment of at least MinExcess.
//
// The target false-positive rate is per honest player-match at the flag threshold. Z values
// were set from the synthetic honest corpus (carthago-sim -calibrate) with a margin over the
// largest honest score seen; every pilot re-fits them on its own honest population before
// the review queue relies on them (strategy E4).
type Threshold struct {
	Z         float64
	MinExcess float64
	TargetFPR float64
}

// Segment names a calibration population: game mode and input device.
type Segment struct {
	Mode   pb.GameMode
	Device pb.InputDevice
}

func (s Segment) String() string {
	return ModeName(s.Mode) + "/" + DeviceName(s.Device)
}

// ModeName is a mode's segment spelling.
func ModeName(m pb.GameMode) string {
	switch m {
	case pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER:
		return "competitive_shooter"
	case pb.GameMode_GAME_MODE_EXTRACTION:
		return "extraction"
	}
	return "unspecified_mode"
}

// DeviceName is an input device's segment spelling.
func DeviceName(d pb.InputDevice) string {
	switch d {
	case pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD:
		return "mouse_keyboard"
	case pb.InputDevice_INPUT_DEVICE_CONTROLLER:
		return "controller"
	case pb.InputDevice_INPUT_DEVICE_TOUCH:
		return "touch"
	}
	return "unspecified_device"
}

// TargetFPR is the false-flag budget for every calibrated segment: at most 1 honest
// player-match in 1,000 reaches the review queue on this rule alone.
const TargetFPR = 1e-3

// DefaultThresholds are the version 1 segments. Founder decision (2026-11-10): competitive
// shooters and extraction games are calibrated first. Controllers get a higher bar because
// aim assistance changes aim dynamics and the segment has less honest data; segments without
// a declared mode or device fall back to the strictest bar.
func DefaultThresholds() map[Segment]Threshold {
	shooter, extraction := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, pb.GameMode_GAME_MODE_EXTRACTION
	mouse, pad := pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD, pb.InputDevice_INPUT_DEVICE_CONTROLLER
	return map[Segment]Threshold{
		{shooter, mouse}:    {Z: 4.0, MinExcess: 0.06, TargetFPR: TargetFPR},
		{shooter, pad}:      {Z: 4.5, MinExcess: 0.08, TargetFPR: TargetFPR},
		{extraction, mouse}: {Z: 4.0, MinExcess: 0.06, TargetFPR: TargetFPR},
		{extraction, pad}:   {Z: 4.5, MinExcess: 0.08, TargetFPR: TargetFPR},
	}
}

// FallbackThreshold applies to segments without their own calibration.
var FallbackThreshold = Threshold{Z: 5.0, MinExcess: 0.10, TargetFPR: TargetFPR}

// Calibrated reports whether a segment has its own thresholds.
func (c *Config) Calibrated(s Segment) bool {
	_, ok := c.Thresholds[s]
	return ok
}

func (c *Config) threshold(s Segment) Threshold {
	if t, ok := c.Thresholds[s]; ok {
		return t
	}
	return FallbackThreshold
}
