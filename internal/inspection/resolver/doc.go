// Package resolver turns authenticated, structured business intent and
// trusted catalog facts into one closed inspection route.
//
// It is deliberately device independent. In particular, this package has no
// raw-chat, prompt, endpoint, credential, native identifier, command, adapter,
// or dispatch contract. Temporary visual intent is admitted only through the
// temporary observation contract, while persistent changes end at a proposal
// handoff that still requires a separate confirmation workflow.
package resolver
