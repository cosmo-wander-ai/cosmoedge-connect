// Package inspectionproduct is the Operator-owned composition root for the
// Inspection v2 product. It may depend on both Operator state owners and the
// inspection domain; the inspection domain must never import this package.
//
// The product is disabled unless Config.Enabled is explicitly true. Disabled
// construction and lifecycle calls perform no filesystem, credential-provider,
// worker, network, fixture, or device action.
package inspectionproduct
