package rootceremony

import "github.com/Labontese/keyroster/internal/trust"

// CAChanges is the CA-change section of a successor (03-12b). The tests
// pin it before it is written.
func CAChanges(prev, next *trust.Bundle) string { return "" }

// RootSetLine is the root-set line of a successor (03-12b). The tests pin
// it before it is written.
func RootSetLine(prev, next *trust.Bundle) string { return "" }
