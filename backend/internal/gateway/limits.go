package gateway

import (
	"fmt"
	"net"
	"sync"
	"time"

	pb "carthago/backend/gen/carthago/v1"
)

// Bounds on what one client connection may send. Everything here is read before or
// without authentication of the player, so each field has a hard cap well above what the
// SDK produces.
const (
	helloReadLimit   = 512 << 10 // Hello with an AK enrollment and EK certificates
	proveReadLimit   = 4 << 20   // Prove with a TPM quote and the boot event log
	sessionReadLimit = 128 << 10 // heartbeats

	maxShortString  = 128
	maxTPMBlob      = 4 << 10
	maxCertBytes    = 16 << 10
	maxEKCerts      = 8
	maxEKChainCerts = 16

	// The SDK sends at most 96 findings with a 47-byte detail per heartbeat and one
	// coverage entry per scan job.
	maxHeartbeatFindings = 128
	maxFindingDetail     = 64
	maxJobName           = 64
	maxCoverageEntries   = 64

	// Handshakes in progress hold up to a 4 MiB frame and run TPM verification, so they are
	// bounded in total and per remote address (a stalled handshake holds its slot until the
	// Hello or Prove timeout). One address may start twice the per-address limit at once
	// and a sixteenth of it per second after that (64 at once, then 2 per second by default).
	defaultMaxHandshakes      = 1024
	defaultMaxHandshakesPerIP = 32
)

// handshakeGate counts handshakes in progress, in total and per remote address, and limits
// how fast one address may start them. Every completed handshake creates a session and
// possibly a device row without any authentication of the player, so the start rate is
// what bounds store growth caused by one address.
type handshakeGate struct {
	mu       sync.Mutex
	total    int
	perIP    map[string]int
	started  map[string]*startBucket
	max      int
	maxPerIP int
	// burst handshakes may start at once from one address, then perSecond per second.
	burst     float64
	perSecond float64
	now       func() time.Time
}

type startBucket struct {
	tokens float64
	last   time.Time
}

func newHandshakeGate(max, maxPerIP int) *handshakeGate {
	return &handshakeGate{perIP: map[string]int{}, started: map[string]*startBucket{}, max: max, maxPerIP: maxPerIP,
		burst: float64(2 * maxPerIP), perSecond: float64(maxPerIP) / 16, now: time.Now}
}

func remoteIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func (h *handshakeGate) acquire(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= h.max || h.perIP[ip] >= h.maxPerIP {
		return false
	}
	now := h.now()
	b := h.started[ip]
	if b == nil {
		if len(h.started) >= 50_000 {
			for k, o := range h.started {
				if now.Sub(o.last).Seconds()*h.perSecond >= h.burst {
					delete(h.started, k)
				}
			}
		}
		b = &startBucket{tokens: h.burst, last: now}
		h.started[ip] = b
	}
	b.tokens = min(h.burst, b.tokens+now.Sub(b.last).Seconds()*h.perSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	h.total++
	h.perIP[ip]++
	return true
}

func (h *handshakeGate) release(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total--
	if h.perIP[ip]--; h.perIP[ip] <= 0 {
		delete(h.perIP, ip)
	}
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validateHello bounds every variable-length Hello field. Version, tenant, ephemeral key
// and device key are checked by the caller.
func validateHello(h *pb.Hello) error {
	if n := len(h.PlayerIdHash); n == 0 || n > 128 {
		return reject("bad_hello", "player_id_hash must be 1-128 bytes")
	}
	// The hash is logged, stored and shown in the dashboard.
	if !printableASCII(h.PlayerIdHash) {
		return reject("bad_hello", "player_id_hash must be printable ASCII without spaces")
	}
	for name, s := range map[string]string{"sdk_version": h.SdkVersion, "build_id": h.BuildId} {
		if len(s) > maxShortString {
			return reject("bad_hello", "%s longer than %d bytes", name, maxShortString)
		}
	}
	if e := h.Env; e != nil && (len(e.OsBuild) > maxShortString || len(e.TpmManufacturer) > maxShortString) {
		return reject("bad_hello", "env report field longer than %d bytes", maxShortString)
	}
	enr := h.TpmEnrollment
	if enr == nil {
		return nil
	}
	if len(enr.TpmManufacturer) > maxShortString || len(enr.TpmFirmware) > maxShortString {
		return reject("bad_hello", "TPM description longer than %d bytes", maxShortString)
	}
	for name, b := range map[string][]byte{"ek_public": enr.EkPublic, "ak_public": enr.AkPublic, "ak_create_data": enr.AkCreateData,
		"ak_create_attestation": enr.AkCreateAttestation, "ak_create_signature": enr.AkCreateSignature} {
		if len(b) > maxTPMBlob {
			return reject("bad_hello", "%s larger than %d bytes", name, maxTPMBlob)
		}
	}
	if len(enr.EkCerts) > maxEKCerts || len(enr.EkChainCerts) > maxEKChainCerts {
		return reject("bad_hello", "too many EK certificates (%d + %d chain)", len(enr.EkCerts), len(enr.EkChainCerts))
	}
	for _, c := range append(append([][]byte{}, enr.EkCerts...), enr.EkChainCerts...) {
		if len(c) > maxCertBytes {
			return reject("bad_hello", "EK certificate larger than %d bytes", maxCertBytes)
		}
	}
	return nil
}

// validateHeartbeat bounds what one heartbeat can hand to the analysis pipeline.
func validateHeartbeat(hb *pb.Heartbeat) error {
	if len(hb.Findings) > maxHeartbeatFindings {
		return fmt.Errorf("%d findings in one heartbeat (limit %d)", len(hb.Findings), maxHeartbeatFindings)
	}
	for _, f := range hb.Findings {
		if len(f.GetDetail()) > maxFindingDetail || len(f.GetJob()) > maxJobName {
			return fmt.Errorf("finding with a %d-byte detail and %d-byte job name", len(f.GetDetail()), len(f.GetJob()))
		}
	}
	if len(hb.Coverage) > maxCoverageEntries {
		return fmt.Errorf("%d coverage entries (limit %d)", len(hb.Coverage), maxCoverageEntries)
	}
	for _, c := range hb.Coverage {
		if len(c.GetJob()) > maxJobName {
			return fmt.Errorf("coverage entry with a %d-byte job name", len(c.GetJob()))
		}
	}
	return nil
}

// heartbeatLimiter bounds how many heartbeats of one session reach the analysis pipeline:
// twice the negotiated rate with a small burst, so heartbeats delayed by the network and
// delivered together still count, while a flood is acknowledged but not analysed.
type heartbeatLimiter struct {
	tokens float64
	last   time.Time
	every  time.Duration
}

const heartbeatBurst = 4

func newHeartbeatLimiter(interval time.Duration, now time.Time) *heartbeatLimiter {
	return &heartbeatLimiter{tokens: heartbeatBurst, last: now, every: interval / 2}
}

func (l *heartbeatLimiter) allow(now time.Time) bool {
	if l.every > 0 {
		l.tokens = min(heartbeatBurst, l.tokens+float64(now.Sub(l.last))/float64(l.every))
	} else {
		l.tokens = heartbeatBurst
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
