package allowlist

import (
	"path"
	"strings"
)

// UnderDir reports whether p is dir or lies under it. dir is a cleaned
// absolute path without a trailing slash; an empty dir contains nothing.
func UnderDir(p, dir string) bool {
	return dir != "" && (p == dir || strings.HasPrefix(p, dir+"/"))
}

// BindSource is a bind source as the runtime records it: cleaned, with
// /var/run mapped to /run as on the node image, where /var/run is a symlink
// containerd resolves. render writes rule sources in this form and the
// sealed plugin compares observed sources in it, so a trailing slash in a
// pod spec never becomes a subtree grant by accident.
func BindSource(p string) string {
	p = path.Clean(p)
	if p == "/var/run" || strings.HasPrefix(p, "/var/run/") {
		return "/run" + strings.TrimPrefix(p, "/var/run")
	}
	return p
}
