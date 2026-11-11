package analyzer

import (
	"fmt"
	"math"
	"time"

	pb "carthago/backend/gen/carthago/v1"
)

// ClientState is what the heartbeat rules remember about one session between heartbeats.
type ClientState struct {
	// local compares the client's clocks with each other, server compares them with the
	// gateway's clock; each runs over its own consecutive windows.
	local, server clockWindow
	lastCPU       uint64
	lastFrame     uint64
	stalled       int
	stalledSince  time.Time
}

type clockPoint struct {
	server time.Time
	qpcNs  uint64
	tickMs uint64
	intr   uint64 // 100 ns
}

// clockWindow measures clock rates over consecutive, non-overlapping windows. A rule fires
// only when two windows in a row are off in the same direction: one late heartbeat, a
// suspend/resume step or a single bad sample disturbs one window (or two in opposite
// directions), while a hooked or accelerated clock is off in every window.
type clockWindow struct {
	base *clockPoint
	prev int // direction the previous window was off in: -1 slow, +1 fast, 0 within tolerance
}

// confirm records this window's direction and reports whether it repeats the previous one.
func (w *clockWindow) confirm(dir int) bool {
	ok := dir != 0 && dir == w.prev
	w.prev = dir
	return ok
}

func direction(ratio, tolerance float64) int {
	switch {
	case ratio > 1+tolerance:
		return 1
	case ratio < 1-tolerance:
		return -1
	}
	return 0
}

const (
	// Window lengths. Client-internal clocks share no network jitter, so half a minute
	// separates a 2% speedhack from noise; comparing against the server clock needs longer
	// because each sample carries up to a heartbeat's worth of network delay. Two windows
	// must agree, so the earliest report is after twice these spans.
	minClockSpan       = 30 * time.Second
	minServerClockSpan = 3 * time.Minute
	stallHeartbeats    = 4
	// minStall is the least time the scan worker must show no CPU before it counts as stalled:
	// with a short heartbeat interval, four heartbeats can fall between two scan periods.
	minStall       = 20 * time.Second
	minInputEvents = 400
)

// Heartbeat evaluates the per-heartbeat rules: time-source divergence (speedhacks that hook
// QPC or GetTickCount, plan §6.1), a scanner that stops making progress while the game keeps
// rendering, and injected mouse input. serverNow is the gateway's receive time.
func (c Config) Heartbeat(st *ClientState, hb *pb.Heartbeat, serverNow time.Time) []Evidence {
	var out []Evidence
	// A sample without the kernel interrupt time (the client's read of it failed) cannot be
	// compared with anything and must not become a baseline.
	if t := hb.Time; t != nil && t.QpcNs != 0 && t.InterruptTime_100Ns != 0 {
		p := clockPoint{server: serverNow, qpcNs: t.QpcNs, tickMs: t.TickCountMs, intr: t.InterruptTime_100Ns}
		out = append(out, c.localClocks(&st.local, &p)...)
		out = append(out, c.serverClock(&st.server, &p)...)
	}
	if s := hb.Sched; s != nil {
		gameplay := hb.Activity == 0
		if gameplay && s.Frames > st.lastFrame && s.WorkerCpuNs == st.lastCPU && st.lastFrame != 0 {
			if st.stalled == 0 {
				st.stalledSince = serverNow
			}
			st.stalled++
		} else {
			st.stalled = 0
		}
		st.lastCPU, st.lastFrame = s.WorkerCpuNs, s.Frames
		if st.stalled >= stallHeartbeats && serverNow.Sub(st.stalledSince) >= minStall {
			st.stalled = 0
			out = append(out, Evidence{Rule: "scanner_stalled", Severity: SeverityMedium, Score: 0.6,
				Summary: fmt.Sprintf("scan worker used no CPU for %s while the game kept rendering", serverNow.Sub(st.stalledSince).Round(time.Second))})
		}
		if s.JobsQuarantined > 0 {
			out = append(out, Evidence{Rule: "scan_quarantined", Severity: SeverityLow, Score: 0.3,
				Summary: fmt.Sprintf("%d scan job(s) quarantined for overrunning their budget", s.JobsQuarantined)})
		}
	}
	for _, j := range hb.Coverage {
		if j.Quarantined && j.RunsCompleted < c.CoverageMinRuns {
			out = append(out, Evidence{Rule: "scan_coverage", Severity: SeverityLow, Score: 0.35,
				Summary: fmt.Sprintf("job %s quarantined before completing a pass: no coverage from it", j.Job)})
		}
	}
	if in := hb.Input; in != nil && in.MouseEvents >= minInputEvents {
		frac := float64(in.Injected) / float64(in.MouseEvents)
		if frac > 0.5 {
			out = append(out, Evidence{Rule: "injected_input", Severity: SeverityMedium, Score: math.Min(0.95, frac),
				Summary: fmt.Sprintf("%.0f%% of %d mouse events injected while focused (%d from lower integrity)", 100*frac, in.MouseEvents, in.LowerIlInjected)})
		}
	}
	return out
}

// backwards reports a client clock that went back: a restart of the client or the machine, or
// a counter that wrapped. The window starts again instead of subtracting across it.
func backwards(a, b *clockPoint) bool {
	return b.qpcNs < a.qpcNs || b.intr < a.intr || b.tickMs < a.tickMs
}

// localClocks compares QPC and GetTickCount with the kernel interrupt time. The interrupt time
// is read straight from KUSER_SHARED_DATA, so a user-mode hook cannot speed it up; the other
// two drifting from it window after window is a hooked time source.
func (c Config) localClocks(w *clockWindow, p *clockPoint) []Evidence {
	a := w.base
	if a == nil || backwards(a, p) {
		*w = clockWindow{base: p}
		return nil
	}
	intr := float64(p.intr-a.intr) * 100
	if intr < float64(minClockSpan) {
		return nil
	}
	w.base = p
	qpc := float64(p.qpcNs-a.qpcNs) / intr
	dir, r, name, tol := direction(qpc, c.ClockToleranceRatio), qpc, "QPC", c.ClockToleranceRatio
	if dir == 0 && a.tickMs != 0 {
		// GetTickCount advances in steps of up to 16 ms, hence the wider band.
		tick := float64(p.tickMs-a.tickMs) * 1e6 / intr
		dir, r, name, tol = direction(tick, c.ClockToleranceRatio+0.01), tick, "GetTickCount", c.ClockToleranceRatio+0.01
	}
	if !w.confirm(dir) {
		return nil
	}
	return []Evidence{{Rule: "time_source_divergence", Severity: SeverityCritical, Score: score(math.Abs(r-1), tol), Integrity: true,
		Summary: fmt.Sprintf("%s runs at %.3fx the kernel interrupt time in two consecutive windows", name, r)}}
}

// serverClock compares the interrupt time with the gateway's clock. All three client clocks
// agreeing but running fast against the server means the whole machine is accelerated (a
// kernel speedhack or a VM clock).
func (c Config) serverClock(w *clockWindow, p *clockPoint) []Evidence {
	a := w.base
	if a == nil || backwards(a, p) || !p.server.After(a.server) {
		*w = clockWindow{base: p}
		return nil
	}
	server := p.server.Sub(a.server)
	if server < minServerClockSpan {
		return nil
	}
	w.base = p
	r := float64(p.intr-a.intr) * 100 / float64(server)
	if !w.confirm(direction(r, c.ClockToleranceRatio)) {
		return nil
	}
	return []Evidence{{Rule: "clock_drift", Severity: SeverityHigh, Score: score(math.Abs(r-1), c.ClockToleranceRatio),
		Summary: fmt.Sprintf("client clock runs at %.3fx the server clock in two consecutive windows of %s", r, server.Round(time.Second))}}
}
