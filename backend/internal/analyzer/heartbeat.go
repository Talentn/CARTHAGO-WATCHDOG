package analyzer

import (
	"fmt"
	"math"
	"time"

	pb "sentinel/backend/gen/sentinel/v1"
)

// ClientState is what the heartbeat rules remember about one session between heartbeats.
type ClientState struct {
	base      *clockPoint
	lastCPU   uint64
	lastFrame uint64
	stalled   int
}

type clockPoint struct {
	server time.Time
	qpcNs  uint64
	tickMs uint64
	intr   uint64 // 100 ns
}

const (
	// minClockSpan: client-internal clocks share no network jitter, so a minute separates a 2%
	// speedhack from noise; comparing against the server clock needs longer because each
	// sample carries up to a heartbeat's worth of network delay.
	minClockSpan       = time.Minute
	minServerClockSpan = 3 * time.Minute
	stallHeartbeats    = 4
	minInputEvents     = 400
)

// Heartbeat evaluates the per-heartbeat rules: time-source divergence (speedhacks that hook
// QPC or GetTickCount, plan §6.1), a scanner that stops making progress while the game keeps
// rendering, and injected mouse input. serverNow is the gateway's receive time.
func (c Config) Heartbeat(st *ClientState, hb *pb.Heartbeat, serverNow time.Time) []Evidence {
	var out []Evidence
	if t := hb.Time; t != nil && t.QpcNs != 0 {
		p := clockPoint{server: serverNow, qpcNs: t.QpcNs, tickMs: t.TickCountMs, intr: t.InterruptTime_100Ns}
		if st.base == nil || p.qpcNs < st.base.qpcNs || p.intr < st.base.intr {
			st.base = &p
		} else {
			out = append(out, c.clocks(st.base, &p)...)
		}
	}
	if s := hb.Sched; s != nil {
		gameplay := hb.Activity == 0
		if gameplay && s.Frames > st.lastFrame && s.WorkerCpuNs == st.lastCPU && st.lastFrame != 0 {
			st.stalled++
		} else {
			st.stalled = 0
		}
		st.lastCPU, st.lastFrame = s.WorkerCpuNs, s.Frames
		if st.stalled == stallHeartbeats {
			out = append(out, Evidence{Rule: "scanner_stalled", Severity: SeverityMedium, Score: 0.6,
				Summary: fmt.Sprintf("scan worker used no CPU for %d heartbeats while the game kept rendering", stallHeartbeats)})
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

func (c Config) clocks(a, b *clockPoint) []Evidence {
	var out []Evidence
	server := b.server.Sub(a.server)
	qpc := float64(b.qpcNs - a.qpcNs)
	intr := float64(b.intr-a.intr) * 100
	tick := float64(b.tickMs-a.tickMs) * 1e6
	if intr >= float64(minClockSpan) {
		// The interrupt time is read straight from KUSER_SHARED_DATA, so a user-mode hook cannot
		// speed it up; QPC and GetTickCount drifting from it is a hooked time source.
		if r := qpc / intr; math.Abs(r-1) > c.ClockToleranceRatio {
			out = append(out, Evidence{Rule: "time_source_divergence", Severity: SeverityCritical, Score: score(math.Abs(r-1), c.ClockToleranceRatio), Integrity: true,
				Summary: fmt.Sprintf("QPC runs at %.3fx the kernel interrupt time", r)})
		} else if a.tickMs != 0 {
			if r := tick / intr; math.Abs(r-1) > c.ClockToleranceRatio+0.01 {
				out = append(out, Evidence{Rule: "time_source_divergence", Severity: SeverityCritical, Score: score(math.Abs(r-1), c.ClockToleranceRatio), Integrity: true,
					Summary: fmt.Sprintf("GetTickCount runs at %.3fx the kernel interrupt time", r)})
			}
		}
	}
	if server >= minServerClockSpan {
		// All three client clocks agreeing but running fast against the server means the
		// whole machine is accelerated (a kernel speedhack or a VM clock).
		if r := intr / float64(server); math.Abs(r-1) > c.ClockToleranceRatio {
			out = append(out, Evidence{Rule: "clock_drift", Severity: SeverityHigh, Score: score(math.Abs(r-1), c.ClockToleranceRatio),
				Summary: fmt.Sprintf("client clock runs at %.3fx the server clock over %s", r, server.Round(time.Second))})
		}
	}
	return out
}
