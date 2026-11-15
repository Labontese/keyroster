package trust

// ActiveCA returns b's active CA entry for role, or the zero entry when b
// has none (03-12b). The tests pin it before it is written.
func ActiveCA(b *Bundle, role string) CAEntry { return CAEntry{} }

// IssuingCAs returns b's active and next CA entries for role, in
// generation order (03-12b). The tests pin it before it is written.
func IssuingCAs(b *Bundle, role string) []CAEntry { return nil }

// checkCATransitions is the chain rule for CA entries (03-12b). The tests
// pin it before it is written; nothing calls it yet.
func checkCATransitions(prev, next *Bundle) error { return nil }
