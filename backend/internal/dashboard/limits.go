package dashboard

import (
	"crypto/sha256"
	"strings"
	"sync"
	"time"
)

// Sign-in attempts are limited twice, in memory:
//
//   - per address: addrMaxFailures failed attempts within failureReset, then refused
//     until the window has passed;
//   - per account: maxFailures failed attempts lock the account for lockBase, and every
//     further failure after that locks it for twice as long, up to lockMax. The lock is
//     keyed on the studio and user name as typed, whether or not such an account exists,
//     so it tells an outsider nothing about which names are real.
//
// A correct password does not get through a lock: that is what makes it a lock. The cost
// is that someone who knows a user name can keep that account locked by failing on
// purpose; the address limit slows them down and the audit log shows it.
const (
	maxFailures     = 5
	addrMaxFailures = 20
	failureReset    = 10 * time.Minute
	lockBase        = time.Minute
	lockMax         = time.Hour
	// acctForget: an account's failure count starts again this long after its last failure.
	acctForget   = 2 * time.Hour
	maxAddrSlots = 10_000
	maxAcctSlots = 100_000
)

type acctKey [sha256.Size]byte

// accountKey names an account for the limiter. A hash keeps arbitrary typed input out of
// the map and makes every key the same size.
func accountKey(tenant, name string) acctKey {
	return sha256.Sum256([]byte(tenant + "\x00" + strings.ToLower(name)))
}

type addrFails struct {
	n     int
	first time.Time
}

type acctFails struct {
	n     int
	locks int
	last  time.Time
	until time.Time
}

type limiter struct {
	mu   sync.Mutex
	addr map[string]addrFails
	acct map[acctKey]acctFails
}

// blocked reports whether an attempt from addr on acct must be refused without looking at
// the credentials.
func (l *limiter) blocked(addr string, acct acctKey, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.addrBlockedLocked(addr, now) {
		return true
	}
	if f, ok := l.acct[acct]; ok {
		if now.Sub(f.last) > acctForget {
			delete(l.acct, acct)
		} else if now.Before(f.until) {
			return true
		}
	}
	return false
}

func (l *limiter) addrBlockedLocked(addr string, now time.Time) bool {
	if f, ok := l.addr[addr]; ok {
		if now.Sub(f.first) > failureReset {
			delete(l.addr, addr)
		} else if f.n >= addrMaxFailures {
			return true
		}
	}
	return false
}

// addrBlocked and addrFailed are the address half alone, for requests that name no
// account (opening a one-time link).
func (l *limiter) addrBlocked(addr string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addrBlockedLocked(addr, now)
}

func (l *limiter) addrFailed(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrFailedLocked(addr, now)
}

func (l *limiter) addrFailedLocked(addr string, now time.Time) {
	if l.addr == nil {
		l.addr = map[string]addrFails{}
	}
	if len(l.addr) >= maxAddrSlots {
		for k, f := range l.addr {
			if now.Sub(f.first) > failureReset {
				delete(l.addr, k)
			}
		}
		// Still full of live entries (failures from very many addresses): start over
		// rather than grow without bound.
		if len(l.addr) >= maxAddrSlots {
			l.addr = map[string]addrFails{}
		}
	}
	a := l.addr[addr]
	if a.n == 0 || now.Sub(a.first) > failureReset {
		a = addrFails{first: now}
	}
	a.n++
	l.addr[addr] = a
}

// failed records a failed attempt and returns how long the account is now locked for
// (zero when this failure did not lock it).
func (l *limiter) failed(addr string, acct acctKey, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrFailedLocked(addr, now)
	if l.acct == nil {
		l.acct = map[acctKey]acctFails{}
	}
	if len(l.acct) >= maxAcctSlots {
		for k, f := range l.acct {
			if now.Sub(f.last) > acctForget {
				delete(l.acct, k)
			}
		}
		if len(l.acct) >= maxAcctSlots {
			l.acct = map[acctKey]acctFails{}
		}
	}
	f := l.acct[acct]
	if now.Sub(f.last) > acctForget {
		f = acctFails{}
	}
	f.n++
	f.last = now
	var lock time.Duration
	if f.n >= maxFailures {
		lock = lockMax
		if f.locks < 6 { // 1, 2, 4, 8, 16, 32 minutes, then the cap
			lock = lockBase << f.locks
		}
		f.locks++
		f.until = now.Add(lock)
	}
	l.acct[acct] = f
	return lock
}

// succeeded clears the account's failures. The address keeps its count: otherwise one
// valid account would let its owner reset the limit between guesses at other accounts.
func (l *limiter) succeeded(acct acctKey) {
	l.mu.Lock()
	delete(l.acct, acct)
	l.mu.Unlock()
}
