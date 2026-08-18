package overenc

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// CanonicalUpstreamURL normalises an http(s) upstream base URL to the one
// committed spelling of its destination, so the same destination has exactly
// one transcript commitment and different destinations differ:
//
//   - scheme and host lowercased
//   - default port elided (:80 for http, :443 for https); other ports kept;
//     a port outside 1-65535 rejected (a forwarding destination has a real
//     port)
//   - one trailing root dot stripped from the host
//   - percent-encoded unreserved characters decoded and dot-segments
//     resolved (RFC 3986 §6.2.2.3, §5.2.4); trailing slashes trimmed
//   - userinfo, query, and fragment rejected: a forwarding destination
//     carries none of them, and committing them verbatim would fork the pin
//
// Every producer and consumer of the commitment canonicalises with this one
// function: the backend dials and commits the result, and the verify CLI
// canonicalises --expected-upstream with it before comparing.
func CanonicalUpstreamURL(raw string) (string, error) {
	// net/url drops a bare trailing "#", so the fragment check must see the
	// raw string: any "#" introduces a fragment.
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("upstream URL %q carries a fragment: the committed destination is a base URL only", raw)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("upstream URL %q does not parse: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("upstream must be an http:// or https:// URL, got %q", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("upstream URL %q carries userinfo: the committed destination names no credentials", raw)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("upstream URL %q carries a query: the committed destination is a base URL only", raw)
	}
	host := CanonicalDNSName(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("upstream URL %q has no host", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	if port := u.Port(); port != "" {
		// url.Parse rejects non-numeric ports; Atoi errors on range overflow.
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("upstream URL %q carries port %q: a forwarding destination has a real port (1-65535)", raw, port)
		}
		if !defaultPort(u.Scheme, n) {
			host += ":" + strconv.Itoa(n)
		}
	}
	return u.Scheme + "://" + host + canonicalBasePath(u.EscapedPath()), nil
}

func defaultPort(scheme string, port int) bool {
	return scheme == "http" && port == 80 || scheme == "https" && port == 443
}

// CanonicalDNSName is the host half of CanonicalUpstreamURL, applied to the
// https upstream server name too: lowercased, one trailing root dot stripped.
func CanonicalDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// canonicalBasePath resolves the base URL's path to the prefix Forward
// appends the request path to: percent-encoded unreserved characters decoded,
// dot-segments resolved, trailing slashes trimmed.
func canonicalBasePath(escaped string) string {
	return strings.TrimRight(removeDotSegments(decodeUnreserved(escaped)), "/")
}

// decodeUnreserved decodes only the percent-triplets RFC 3986 calls
// unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~"), so %2e participates in
// dot-segment resolution while reserved encodings like %2F stay distinct.
func decodeUnreserved(escaped string) string {
	if !strings.Contains(escaped, "%") {
		return escaped
	}
	var out strings.Builder
	out.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '%' && i+2 < len(escaped) {
			hi, ok1 := unhex(escaped[i+1])
			lo, ok2 := unhex(escaped[i+2])
			if ok1 && ok2 && isUnreserved(hi<<4|lo) {
				out.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		out.WriteByte(escaped[i])
	}
	return out.String()
}

func unhex(b byte) (byte, bool) {
	switch {
	case '0' <= b && b <= '9':
		return b - '0', true
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10, true
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// removeDotSegments is RFC 3986 §5.2.4 for an absolute path: "." segments
// drop, ".." pops one segment and cannot climb above the root.
func removeDotSegments(path string) string {
	if !strings.HasPrefix(path, "/") {
		return path
	}
	var segs []string
	for _, seg := range strings.Split(path[1:], "/") {
		switch seg {
		case ".":
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, seg)
		}
	}
	return "/" + strings.Join(segs, "/")
}
