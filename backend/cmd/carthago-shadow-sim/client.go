package main

import "carthago/backend/internal/sim/simclient"

// The simulated client is shared with carthago-demo.
type (
	deviceKey = simclient.DeviceKey
	player    = simclient.Player
	seen      = simclient.Seen
)

var (
	newDeviceKey = simclient.NewDeviceKey
	signIn       = simclient.SignIn
	errBanned    = simclient.ErrBanned
)
