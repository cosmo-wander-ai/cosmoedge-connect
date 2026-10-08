// Package inspectionfixture assembles a device-independent, single-process
// Inspection v2 business fixture. It uses the production Product, Host, HTTP
// API and persistent stores while replacing every device- or channel-reaching
// adapter with a closed local fixture implementation.
//
// The package is intentionally not imported by ordinary product composition.
// It exists to exercise the complete business path before cameras or edge
// devices are available, without granting any persistent device-write port.
package inspectionfixture
