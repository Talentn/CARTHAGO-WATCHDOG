package dashboard

import (
	"context"
	"errors"

	"carthago/backend/internal/store"
)

// driverCard is the "Kernel drivers" card of a session: how the gateway read the driver
// list the client sent at the handshake, what it raised in it, and the list itself.
type driverCard struct {
	List *store.DriverList
	// Flagged are the drivers raised for review, in load order.
	Flagged []store.ListedDriver
	// Attested is what the unattested pool answers for this session; PoolOn whether the
	// studio has that pool on.
	Attested, PoolOn bool
}

func (c driverCard) HasList() bool {
	return c.List.Status == store.DriversVerified || c.List.Status == store.DriversUnverified
}

// driverFlag puts a driver's flag in words.
func driverFlag(f string) string {
	switch f {
	case store.DriverFlagUnsigned:
		return "no signer"
	case store.DriverFlagVulnerable:
		return "known vulnerable"
	case store.DriverFlagTestSigned:
		return "test-signed"
	}
	return f
}

// driverCardFor is nil for a session from before the gateway kept driver lists.
func (s *Server) driverCardFor(ctx context.Context, tenant string, sess *store.Session) (*driverCard, error) {
	l, err := s.st.SessionDriverList(ctx, tenant, sess.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := &driverCard{List: l, Attested: l.Attested()}
	for _, d := range l.Drivers {
		if len(d.Flags) > 0 {
			c.Flagged = append(c.Flagged, d)
		}
	}
	c.PoolOn, err = s.st.UnattestedPool(ctx, tenant)
	return c, err
}
