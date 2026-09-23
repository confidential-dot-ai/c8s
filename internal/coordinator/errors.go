package coordinator

import "errors"

// Error classes callers map to a status code. Every rejection wraps exactly one
// of them, so the HTTP layer never switches on message text.
var (
	// ErrNotFound is an object or a participant that does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is a request that contradicts the current state: a write
	// while an update is outstanding, an enrollment during one, a boot id
	// re-enrolling under a different key, an ack for another update.
	ErrConflict = errors.New("conflicts with the current state")
	// ErrInvalid is a well-formed request whose content is unusable: a
	// non-canonical policy document, a boot id that does not name its key.
	ErrInvalid = errors.New("invalid")
	// ErrUnauthenticated is a participant message whose signature does not
	// verify under the enrolled boot key.
	ErrUnauthenticated = errors.New("signature does not verify")
)
