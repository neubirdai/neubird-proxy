package redact

import "regexp"

// Built-in rules. PII patterns follow Presidio's predefined recognizers;
// secret patterns follow common secret scanners. All are RE2.
//
// Formatted patterns match on shape alone. Context patterns need a keyword
// ("ssn", "phone", "dob", "password") and mask only the value after it,
// through a named group v; they catch the unformatted forms (ssn=219099999)
// that a shape-only pattern would confuse with IDs and counters.

type pattern struct {
	re       *regexp.Regexp
	validate func(string) bool // optional; runs on the masked text
	// find, when set, finds the matches instead of re, which then only
	// documents them (see findPrivateKeys).
	find func(s string, n int) [][]int
	// raw also runs the pattern on the text as written, before decoding:
	// a decoded %40 or %2F in a password ends the value class, so on the
	// decoded text the match stops short of the rest of the secret. rawRe,
	// if set, replaces re there.
	raw   bool
	rawRe *regexp.Regexp
	// Prefilter, so the regex only runs on text that could match: at least
	// one of needles (lowercase) must appear case-insensitively, and the
	// text must hold at least minDigits digits.
	needles   []string
	minDigits int
	// scope limits where the regex runs; see scope constants.
	scope scope
	// before and after size a scopeNeedles window around each needle, in
	// bytes, before it is widened to whitespace. Zero and zero means the
	// whitespace-delimited token holding the needle, for patterns whose
	// match cannot contain whitespace.
	before, after int
}

type scope int

const (
	// scopeWhole runs the regex over the whole string.
	scopeWhole scope = iota
	// scopeDigits runs it only over runs of digits and " ().+-", the only
	// characters a digit-shape match (SSN, card, phone, IPv4) can contain.
	scopeDigits
	// scopeNeedles runs it only over whitespace-bounded windows around each
	// needle occurrence. For patterns whose match sits near the needle.
	scopeNeedles
)

type builtin struct {
	values []pattern
	key    *regexp.Regexp // JSON keys whose whole value is masked
}

const sep = `[^0-9A-Za-z]{0,4}` // between a context keyword and its value

var builtins = map[string]builtin{
	// PII
	"email": {values: []pattern{
		{re: regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}\b`), needles: []string{"@"}, scope: scopeNeedles},
	}},
	"us_ssn": {
		values: []pattern{
			{re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b|\b\d{3} \d{2} \d{4}\b`), validate: validSSN, minDigits: 9, scope: scopeDigits},
			{re: regexp.MustCompile(`(?i)\b(?:ssn|social[ _-]?security(?:[ _-]?(?:no|num|number))?|tin|taxpayer[ _-]?id)\b` + sep + `(?P<v>\d{9}|\d{3}[ .]\d{2}[ .]\d{4})\b`), validate: validSSN,
				needles: []string{"ssn", "social", "tin", "taxpayer"}, minDigits: 9, scope: scopeNeedles, before: 24, after: 40},
		},
		key: regexp.MustCompile(`(?i)^(?:ssn|u_ssn|social_?security(?:_?(?:no|num|number))?|tax_?id|tin)$`),
	},
	"credit_card": {values: []pattern{
		// Issuer prefixes (Visa, Mastercard, Amex, Discover, Diners, JCB)
		// then 13-19 digits in all. Requiring a prefix keeps epoch-ms
		// timestamps (leading 1) and most IDs out; Luhn does the rest.
		{re: regexp.MustCompile(`\b(?:4\d|5[1-5]|2[2-7]|3[0-8]|6[045])(?:[ .-]?\d){11,17}\b`), validate: luhn, minDigits: 13, scope: scopeDigits},
	}},
	"phone_us": {
		values: []pattern{
			{re: regexp.MustCompile(`(?:\+?1[-. ])?(?:\([2-9]\d{2}\) ?|\b[2-9]\d{2}[-. ])[2-9]\d{2}[-. ]\d{4}\b`), minDigits: 10, scope: scopeDigits},
			{re: regexp.MustCompile(`(?i)\b(?:phone|tel|telephone|mobile|cell|fax|ph|contact[ _-]?number)\b[^0-9A-Za-z+]{0,4}(?P<v>\+?1?[2-9]\d{2}[2-9]\d{6})\b`),
				needles: []string{"phone", "tel", "mobile", "cell", "fax", "ph", "contact"}, minDigits: 10, scope: scopeNeedles, before: 16, after: 40},
		},
		key: regexp.MustCompile(`(?i)^(?:phone|phone_?number|mobile|mobile_?phone|cell|cell_?phone|home_?phone|work_?phone|fax|u_phone)$`),
	},
	"ipv4": {values: []pattern{
		{re: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`), minDigits: 4, scope: scopeDigits},
	}},
	"date_of_birth": {
		values: []pattern{
			{re: regexp.MustCompile(`(?i)(?:\b(?:dob|date[ _-]?of[ _-]?birth|birth[ _-]?date|birthday|born(?:[ _-]on)?)\b|\bd\.o\.b\.?)` + sep +
				`(?P<v>\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|` +
				`(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}\.? \d{1,2},? \d{2,4}|` +
				`\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}\.? \d{2,4})`),
				needles: []string{"dob", "birth", "born", "d.o.b"}, minDigits: 2, scope: scopeNeedles, before: 24, after: 48},
		},
		key: regexp.MustCompile(`(?i)^(?:dob|date_?of_?birth|birth_?date|birthday|u_dob)$`),
	},

	// Secrets
	"private_key": {values: []pattern{
		{re: privateKeyRe, find: findPrivateKeys, needles: []string{"private key-----"}},
	}},
	"url_credentials": {values: []pattern{
		{re: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@"'<>]+:(?P<v>[^\s/@"'<>]+)@`), needles: []string{"://"}, scope: scopeNeedles, raw: true},
	}},
	"jwt": {values: []pattern{
		{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`), needles: []string{"eyj"}, scope: scopeNeedles},
	}},
	"bearer_token": {values: []pattern{
		{re: regexp.MustCompile(`(?i)\b(?:bearer|basic|token)\s+(?P<v>[A-Za-z0-9._~+/-]{12,}=*)`), validate: hasDigit,
			needles: []string{"bearer", "basic", "token"}, minDigits: 1, scope: scopeNeedles, before: 1, after: 32},
	}},
	"aws_access_key": {values: []pattern{
		{re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}\b`),
			needles: []string{"akia", "asia", "abia", "acca", "agpa", "aida", "aipa", "anpa", "anva", "apka", "aroa", "asca"}, scope: scopeNeedles},
	}},
	"azure_key": {values: []pattern{
		{re: regexp.MustCompile(`(?i)\b(?:AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/]{20,}={0,2})`), needles: []string{"accesskey=", "accountkey="}, scope: scopeNeedles},
		{re: regexp.MustCompile(`(?i)[?&]sig=(?P<v>[A-Za-z0-9%+/]{16,}={0,2})`), needles: []string{"sig="}, scope: scopeNeedles},
	}},
	"vendor_token": {values: []pattern{
		{re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})\b`),
			needles: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "sk-", "aiza", "glpat-"}, scope: scopeNeedles},
	}},
	"secret_assignment": {
		values: []pattern{
			// A non-alphanumeric boundary (not \b) so db_password=... matches.
			{re: regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|credentials?)["']?\s*[:=]\s*["']?(?P<v>[^\s"'&;,<>]{3,})`),
				needles: []string{"passw", "pwd", "secret", "key", "token", "credential"}, scope: scopeNeedles, before: 16, after: 32,
				// As written, an HTML entity (&amp; &#59;) is part of the
				// value: its & and ; would end it otherwise.
				raw: true, rawRe: regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|credentials?)["']?\s*[:=]\s*["']?(?P<v>(?:[^\s"'&;,<>]|&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});)(?:[^\s"'&;,<>]|&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});){2,})`)},
		},
		key: regexp.MustCompile(`(?i)(?:password|passwd|secret|api_?key|apikey|access_?token|auth_?token|refresh_?token|private_?key|client_?secret|credential)`),
	},

	// Opt-in: noisy on some data, so not in the default set.
	"windows_account": {values: []pattern{
		{re: regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9-]{1,14}\\(?P<v>[A-Za-z][A-Za-z0-9._-]{1,19})\b`), needles: []string{`\`}, scope: scopeNeedles},
	}},
}

// builtinOrder is the default rule set and its precedence: secrets before
// PII, and specific patterns before generic ones, which only affects the
// label when both match the same value.
var builtinOrder = []string{
	"private_key", "jwt", "aws_access_key", "azure_key", "vendor_token", "url_credentials", "bearer_token", "secret_assignment",
	"email", "us_ssn", "credit_card", "phone_us", "ipv4", "date_of_birth",
}

// optionalBuiltins are known but only enabled when listed in builtins.
var optionalBuiltins = []string{"windows_account"}

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

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
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
