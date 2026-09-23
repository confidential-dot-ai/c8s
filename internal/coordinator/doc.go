// Package coordinator is the CDS side of the dynamic allowlist: the public
// journal, the signed state statement, and the private bookkeeping that decides
// when a policy update may switch and complete.
//
// One update is outstanding at a time. Publishing stores the policy object and
// appends a published entry, which widens the advertised bound to source-or-
// target; it authorizes nothing. The update switches — admission, issuance and
// secret release move to the target — once every participant frozen at
// publication has acknowledged its barrier, and completes once every one of
// them reports the target applied. A completion that retires permissions
// appends a drained entry, which narrows the bound back to one policy.
//
// # What it does not do
//
//   - The authority key is generated in memory at Open and never persisted, so
//     a restart is a new authority and every verifier must re-anchor. That is
//     deliberate: an operator-readable database must not hold the signing seed.
//   - A restored database snapshot is undetectable from inside CDS. The chain
//     proves that what a client sees continues the history it already saw, not
//     that no other branch existed.
//   - There is no fencing and no removal. An unreachable participant blocks
//     completion forever, and so blocks the next publication; every ack that
//     leaves one outstanding is logged at warn. Dropping it from Kubernetes or
//     from a registry cannot assert that its workloads stopped.
package coordinator
