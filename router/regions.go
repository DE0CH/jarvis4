package main

// ---- session regions (Deyao, 2026-10-29: "choose per session"; Fly has no Hong Kong region, Singapore and Tokyo
// are the nearest to it) ----

// sessionRegions: the Fly regions New session offers; the router's FLY_REGION (cfg.Region) is the default. Every start
// is a new machine on a new volume from the line's snapshot, so a session's region only says where its next machine
// runs; the router, its database and the snapshots stay in Falkenstein.
var sessionRegions = []struct{ ID, Label string }{{"lhr", "London"}, {"sin", "Singapore"}, {"nrt", "Tokyo"}}

func validRegion(id string) bool {
	for _, g := range sessionRegions {
		if g.ID == id {
			return true
		}
	}
	return false
}

// regionOf: where the session's machines run (its own region, else the router's default)
func (r *Router) regionOf(s *Session) string {
	if s != nil && s.Region != "" {
		return s.Region
	}
	return r.cfg.Region
}
