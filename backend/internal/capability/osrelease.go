package capability

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxOSReleaseLine = 4096

var (
	errOSRelease = errors.New("malformed os-release")
	keyRE        = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// parseOSRelease parses os-release(5) strictly. Any duplicate key, invalid
// quoting or escape, NUL or control character, over-long line or non-UTF-8
// input is an error (probe unknown, OSRELEASE_MALFORMED).
func parseOSRelease(data []byte) (map[string]string, error) {
	if !utf8.Valid(data) {
		return nil, errOSRelease
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > maxOSReleaseLine {
			return nil, errOSRelease
		}
		for _, r := range line {
			if (unicode.IsControl(r) && r != '\t') || r == '\ufeff' {
				return nil, errOSRelease
			}
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, raw, ok := strings.Cut(trimmed, "=")
		if !ok || !keyRE.MatchString(key) {
			return nil, errOSRelease
		}
		if _, dup := out[key]; dup {
			return nil, errOSRelease
		}
		val, err := unquote(raw)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	return out, nil
}

// unquote handles unquoted, "double" (escapes \" \\ \$ \`) and 'single' values.
func unquote(raw string) (string, error) {
	switch {
	case raw == "":
		return "", nil
	case raw[0] == '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' || strings.Contains(raw[1:len(raw)-1], "'") {
			return "", errOSRelease
		}
		return raw[1 : len(raw)-1], nil
	case raw[0] == '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return "", errOSRelease
		}
		var b strings.Builder
		body := raw[1 : len(raw)-1]
		for i := 0; i < len(body); i++ {
			c := body[i]
			if c == '\\' {
				if i+1 >= len(body) || !strings.ContainsRune("\"\\$`", rune(body[i+1])) {
					return "", errOSRelease
				}
				b.WriteByte(body[i+1])
				i++
				continue
			}
			if strings.ContainsRune("\"$`", rune(c)) {
				return "", errOSRelease
			}
			b.WriteByte(c)
		}
		return b.String(), nil
	default:
		if strings.ContainsAny(raw, " \t\"'\\$`") {
			return "", errOSRelease
		}
		return raw, nil
	}
}
