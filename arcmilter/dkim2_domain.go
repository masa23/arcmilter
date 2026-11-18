package arcmilter

import (
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Match mmauth/dkim2's SMTP IDNA profile. Lookup profiles may map invalid
// U-labels into other domains, so they must not be used for signing decisions.
var dkim2IDNA = idna.New(idna.ValidateForRegistration())

// normalizeDKIM2Domain implements draft-09 section 18 for comparison keys.
// The original message and SMTP envelope are still passed unchanged to mmauth.
func normalizeDKIM2Domain(domain string) (string, error) {
	invalid := errors.New("invalid DKIM2 internationalized domain")
	if len(domain) > 4*253 || !utf8.ValidString(domain) {
		return "", invalid
	}
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		ascii := true
		for j := 0; j < len(label); j++ {
			if label[j] >= utf8.RuneSelf {
				ascii = false
				break
			}
		}
		// A-labels are case insensitive. U-labels must be validated as-is;
		// Unicode lowercasing can turn an invalid label into a different one.
		if ascii {
			label = strings.ToLower(label)
			labels[i] = label
		}
		// Reject malformed ACE labels before Punycode decoding as well.
		if strings.HasPrefix(label, "xn--") && !validDKIM2DNSDomain(label) {
			return "", invalid
		}
	}
	ascii, err := dkim2IDNA.ToASCII(strings.Join(labels, "."))
	if err != nil || !validDKIM2DNSDomain(ascii) {
		return "", invalid
	}
	return ascii, nil
}

func validDKIM2DNSDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
