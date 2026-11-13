package analyst

import (
	"testing"

	"carthago/backend/internal/analyzer"
)

// The Oracle's families and the ban tiers agree: nothing it files under play, input,
// timing, the PC's environment or the scanner's health may ban by itself.
func TestStatisticalFamiliesNeverBan(t *testing.T) {
	for rule, fam := range ruleFamily {
		switch fam {
		case FamilyAim, FamilyInformation, FamilyInput, FamilySpeedTime, FamilyEnvironment, FamilyScanner:
			if analyzer.TierOf(rule) != analyzer.TierSuspicious {
				t.Errorf("%s (%s) is in the certain tier", rule, fam)
			}
		}
	}
}
