package directory

// SetForTest installs a snapshot directly. It exists so other packages'
// tests can run against a mock receiver without a network fetch; the
// snapshot must still come from Parse, so validation is never bypassed.
func SetForTest(s *Store, snap *Snapshot) { s.set(snap) }
