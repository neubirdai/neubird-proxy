package redact

import "regexp"

// Built-in patterns follow Presidio's predefined recognizers, restricted to
// formatted identifiers so that IDs, epoch timestamps and counters in
// Splunk and ServiceNow payloads rarely trip them. All are RE2.

type builtin struct {
	value    *regexp.Regexp    // matches inside string values
	validate func(string) bool // optional checksum or range check
	key      *regexp.Regexp    // matches JSON keys whose whole value is masked
}

var builtins = map[string]builtin{
	"email": {
		value: regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}\b`),
	},
	"us_ssn": {
		value:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b|\b\d{3} \d{2} \d{4}\b`),
		validate: validSSN,
	},
	"phone_us": {
		value: regexp.MustCompile(`(?:\+?1[-. ])?(?:\([2-9]\d{2}\) ?|\b[2-9]\d{2}[-. ])[2-9]\d{2}[-. ]\d{4}\b`),
	},
	"credit_card": {
		// Issuer prefixes (Visa, Mastercard, Amex, Discover, Diners, JCB)
		// then 13-19 digits in all. Requiring a prefix keeps epoch-ms
		// timestamps (leading 1) and most IDs out; Luhn does the rest.
		value:    regexp.MustCompile(`\b(?:4\d|5[1-5]|2[2-7]|3[0-8]|6[045])(?:[ -]?\d){11,17}\b`),
		validate: luhn,
	},
	"ipv4": {
		value: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`),
	},
	"date_of_birth": {
		key: regexp.MustCompile(`(?i)^(?:dob|date_?of_?birth|birth_?date|birthday|u_dob)$`),
	},
}

// builtinOrder is the default rule set and its precedence.
var builtinOrder = []string{"email", "us_ssn", "credit_card", "phone_us", "ipv4", "date_of_birth"}

// validSSN rejects numbers the SSA never issues: area 000, 666 or 9xx,
// group 00, serial 0000.
func validSSN(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[0:3], d[3:5], d[5:9]
	switch {
	case area == "000", area == "666", area[0] == '9':
		return false
	case group == "00", serial == "0000":
		return false
	}
	return true
}

func luhn(s string) bool {
	d := digits(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

func digits(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	return string(b)
}
