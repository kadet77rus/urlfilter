package rules

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/miekg/dns"
)

// RuleSyntaxError represents an error while parsing a filtering rule
type RuleSyntaxError struct {
	msg      string
	ruleText string
}

func (e *RuleSyntaxError) Error() string {
	return fmt.Sprintf("syntax error: %s, rule: %s", e.msg, e.ruleText)
}

// ErrUnsupportedRule signals that this might be a valid rule type,
// but it is not yet supported by this library
var ErrUnsupportedRule = errors.New("this type of rules is unsupported")

// Rule is a base interface for all filtering rules
type Rule interface {
	// Text returns the original rule text
	Text() string

	// GetFilterListID returns ID of the filter list this rule belongs to
	GetFilterListID() int
}

// NewRule creates a new filtering rule from the specified line
// It returns nil if the line is empty or if it is a comment
func NewRule(line string, filterListID int) (Rule, error) {
	line = strings.TrimSpace(line)

	if line == "" || isComment(line) {
		return nil, nil
	}

	if isCosmetic(line) {
		return NewCosmeticRule(line, filterListID)
	}

	f, err := NewHostRule(line, filterListID)
	if err == nil {
		return f, nil
	}

	return NewNetworkRule(line, filterListID)
}

// isComment checks if the line is a comment
func isComment(line string) bool {
	if len(line) == 0 {
		return false
	}

	if line[0] == '!' {
		return true
	}

	if line[0] == '#' {
		if len(line) == 1 {
			return true
		}

		// Now we should check that this is not a cosmetic rule
		for _, marker := range cosmeticRulesMarkers {
			if startsAtIndexWith(line, 0, marker) {
				return false
			}
		}

		return true
	}

	return false
}

// loadDomains loads $domain modifier or cosmetic rules domains
// domains is the list of domains
// sep is the separator character. for network rules it is '|', for cosmetic it is ','.
func loadDomains(domains, sep string) (permittedDomains, restrictedDomains []string, err error) {
	if domains == "" {
		err = errors.New("no domains specified")
		return
	}

	list := strings.Split(domains, sep)
	for i := 0; i < len(list); i++ {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if !filterutil.IsDomainName(d) && !strings.HasSuffix(d, ".*") {
			err = fmt.Errorf("invalid domain specified: %s", domains)
			return
		}

		if restricted {
			restrictedDomains = append(restrictedDomains, d)
		} else {
			permittedDomains = append(permittedDomains, d)
		}
	}

	return
}

// strToRR converts s to a DNS resource record (RR) type.  s may be in any
// letter case.
func strToRR(s string) (rr RRType, err error) {
	// TypeNone and TypeReserved are special cases in package dns.
	if strings.EqualFold(s, "none") || strings.EqualFold(s, "reserved") {
		return 0, errors.New("dns rr type is none or reserved")
	}

	rr, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("dns rr type %q is invalid", s)
	}

	return rr, nil
}

// loadDNSTypes loads the $dnstype modifier.  types is the list of types.
func loadDNSTypes(types string) (permittedTypes, restrictedTypes []RRType, err error) {
	if types == "" {
		return nil, nil, errors.New("no dns record types specified")
	}

	list := strings.Split(types, "|")
	for i, rrStr := range list {
		if len(rrStr) == 0 {
			return nil, nil, fmt.Errorf("dns record type %d is empty", i)
		}

		restricted := rrStr[0] == '~'
		if restricted {
			rrStr = rrStr[1:]
		}

		rr, err := strToRR(rrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("type %d (%q): %w", i, rrStr, err)
		}

		if restricted {
			restrictedTypes = append(restrictedTypes, rr)
		} else {
			permittedTypes = append(permittedTypes, rr)
		}
	}

	return permittedTypes, restrictedTypes, nil
}

// loadDNSRewrite loads the $dnsrewrite modifier.
func loadDNSRewrite(s string) (rewrite *DNSRewrite, err error) {
	parts := strings.SplitN(s, ";", 3)
	switch len(parts) {
	case 1:
		return loadDNSRewriteShort(s)
	case 2:
		return nil, errors.New("invalid dnsrewrite: expected zero or two delimiters")
	case 3:
		return loadDNSRewriteNormal(parts[0], parts[1], parts[2])
	default:
		// TODO(a.garipov): Use panic("unreachable") instead?
		return nil, fmt.Errorf("SplitN returned %d parts", len(parts))
	}
}

// allUppercaseASCII returns true if s is not empty and all characters in s are
// uppercase ASCII letters.
func allUppercaseASCII(s string) (ok bool) {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}

	return true
}

// loadDNSRewritesShort loads the shorthand version of the $dnsrewrite modifier.
func loadDNSRewriteShort(s string) (rewrite *DNSRewrite, err error) {
	if s == "" {
		// Return an empty DNSRewrite, because an empty string most
		// probalby means that this is a disabling allowlist case.
		return &DNSRewrite{}, nil
	} else if allUppercaseASCII(s) {
		if s == "REFUSED" {
			return &DNSRewrite{
				RCode: dns.RcodeRefused,
			}, nil
		}

		return nil, fmt.Errorf("unknown keyword: %q", s)
	}

	ip := net.ParseIP(s)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &DNSRewrite{
				RCode:  dns.RcodeSuccess,
				RRType: dns.TypeA,
				Value:  ip,
			}, nil
		}

		return &DNSRewrite{
			RCode:  dns.RcodeSuccess,
			RRType: dns.TypeAAAA,
			Value:  ip,
		}, nil
	}

	return &DNSRewrite{
		NewCNAME: s,
	}, nil
}

// loadDNSRewritesNormal loads the normal version for of the $dnsrewrite
// modifier.
func loadDNSRewriteNormal(rcodeStr, rrStr, valStr string) (rewrite *DNSRewrite, err error) {
	rcode, ok := dns.StringToRcode[strings.ToUpper(rcodeStr)]
	if !ok {
		return nil, fmt.Errorf("unknown rcode: %q", rcodeStr)
	}

	if rcode != dns.RcodeSuccess {
		return &DNSRewrite{
			RCode: rcode,
		}, nil
	}

	rr, err := strToRR(rrStr)
	if err != nil {
		return nil, err
	}

	switch rr {
	case dns.TypeA:
		ip := net.ParseIP(valStr)
		if ip4 := ip.To4(); ip4 == nil {
			return nil, fmt.Errorf("invalid ipv4: %q", valStr)
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  ip,
		}, nil
	case dns.TypeAAAA:
		ip := net.ParseIP(valStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv6: %q", valStr)
		} else if ip4 := ip.To4(); ip4 != nil {
			return nil, fmt.Errorf("want ipv6, got ipv4: %q", valStr)
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  ip,
		}, nil
	case dns.TypeCNAME:
		return &DNSRewrite{
			NewCNAME: valStr,
		}, nil
	case dns.TypeTXT:
		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  valStr,
		}, nil
	default:
		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
		}, nil
	}
}

// isValidCTag - returns TRUE if ctag value format is correct: a-z0-9_
func isValidCTag(s string) bool {
	for _, ch := range s {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '_') {
			return false
		}
	}
	return true
}

// loadCTags loads tags from the $ctag modifier
// value: string value of the $ctag modifier
// sep: separator character; for network rules it is '|'
// returns sorted arrays with permitted and restricted $ctag
func loadCTags(value, sep string) (permittedCTags, restrictedCTags []string, err error) {
	if value == "" {
		err = errors.New("value is empty")
		return
	}

	list := strings.Split(value, sep)
	for i := 0; i < len(list); i++ {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if !isValidCTag(d) {
			err = fmt.Errorf("invalid ctag specified: %s", value)
			return
		}

		if restricted {
			restrictedCTags = append(restrictedCTags, d)
		} else {
			permittedCTags = append(permittedCTags, d)
		}
	}

	// Sorting tags so that we could use binary search
	sort.Strings(permittedCTags)
	sort.Strings(restrictedCTags)

	return
}

// The $client modifier allows specifying clients this rule will be working for.
// It accepts client names, IP addresses, or CIDR address ranges.
//
// The syntax is:
//
// $client=value1|value2|...
// You can also specify "restricted" clients by adding a ~ character before the client IP or name.
// In this case, the rule will not be applied to this client's requests.
//
// $client=~value1
//
// ## Specifying client names
// Client names usually contain spaces or other special characters, that's why you
// should enclose the name in quotes (both double-quotes and single-quotes are supported).
// If the client name contains quotes, use `\` to escape them.
// Also, you need to escape commas (`,`) and pipes (`|`).
//
// Please note, that when specifying a "restricted" client, you must keep `~` out of the quotes.
//
// Examples of the input value:
// 127.0.0.1
// 192.168.3.0/24
// ::
// fe01::/64
// 'Frank\'s laptop'
// "Frank's phone"
// ~'Mary\'s\, John\'s\, and Boris\'s laptops'
// ~Mom|~Dad|"Kids"
//
// Returns sorted arrays of permitted and restricted clients
func loadClients(value string, sep byte) (permittedClients, restrictedClients *clients, err error) {
	if value == "" {
		err = errors.New("value is empty")
		return
	}

	// First of all, split by the specified separator
	list := splitWithEscapeCharacter(value, sep, '\\', false)
	for _, s := range list {
		restricted := false
		client := s

		// 1. Check if this is a restricted or permitted client
		if strings.HasPrefix(client, "~") {
			restricted = true
			client = client[1:]
		}

		// 2. Check if quoted
		quoteChar := uint8(0)
		if len(client) >= 2 &&
			(client[0] == '\'' || client[0] == '"') &&
			client[0] == client[len(client)-1] {
			quoteChar = client[0]
		}

		// 3. If quoted, remove quotes
		if quoteChar > 0 {
			client = client[1 : len(client)-1]
		}

		// 4. Unescape commas and quotes
		client = strings.ReplaceAll(client, "\\,", ",")
		if quoteChar > 0 {
			client = strings.ReplaceAll(client, "\\"+string(quoteChar), string(quoteChar))
		}

		if client == "" {
			err = fmt.Errorf("invalid $client value %s", value)
			return
		}

		if restricted {
			if restrictedClients == nil {
				restrictedClients = &clients{}
			}
			restrictedClients.add(client)
		} else {
			if permittedClients == nil {
				permittedClients = &clients{}
			}
			permittedClients.add(client)
		}
	}

	permittedClients.finalize()
	restrictedClients.finalize()

	return
}
