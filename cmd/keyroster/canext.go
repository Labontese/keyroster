package main

import "github.com/Labontese/keyroster/internal/trust"

// parseCANextFile reads the prepare file of root sign --ca-next strictly
// (03-12b). The tests pin it before it is written.
func parseCANextFile(data []byte) (trust.CAEntry, error) { return trust.CAEntry{}, nil }

// readCANextFile reads the prepare file at path (03-12b). The tests pin it
// before it is written.
func readCANextFile(path string) (trust.CAEntry, error) { return trust.CAEntry{}, nil }
