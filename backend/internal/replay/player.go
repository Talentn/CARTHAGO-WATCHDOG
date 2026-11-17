package replay

import _ "embed"

// PlayerJS is the script that plays a recording in a browser: it draws the match from
// above on a canvas and lets the viewer play, pause, scrub and jump. The dashboard's match
// page and the community review page both serve it from their own origin; it loads
// nothing else and sends nothing anywhere.
//
//go:embed player.js
var PlayerJS []byte
