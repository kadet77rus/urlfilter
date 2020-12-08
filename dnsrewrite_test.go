package urlfilter

import (
	"net"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDNSEngine_MatchRequest_dnsRewrite(t *testing.T) {
	const rulesText = `
|short_v4^$dnsrewrite=127.0.0.1
|short_v4_multiple^$dnsrewrite=127.0.0.1
|short_v4_multiple^$dnsrewrite=127.0.0.2
|normal_v4^$dnsrewrite=NOERROR;A;127.0.0.1
|normal_v4_multiple^$dnsrewrite=NOERROR;A;127.0.0.1
|normal_v4_multiple^$dnsrewrite=NOERROR;A;127.0.0.2

|short_v6^$dnsrewrite=::1
|short_v6_multiple^$dnsrewrite=::1
|short_v6_multiple^$dnsrewrite=::2
|normal_v6^$dnsrewrite=NOERROR;AAAA;::1
|normal_v6_multiple^$dnsrewrite=NOERROR;AAAA;::1
|normal_v6_multiple^$dnsrewrite=NOERROR;AAAA;::2

|refused_host^$dnsrewrite=REFUSED
|new_cname^$dnsrewrite=othercname
|new_txt^$dnsrewrite=NOERROR;TXT;new_txtcontent

|priority^$client=127.0.0.1
|priority^$dnsrewrite=127.0.0.1

|https_type^$dnstype=HTTPS,dnsrewrite=REFUSED

|disable_one^$dnsrewrite=127.0.0.1
|disable_one^$dnsrewrite=127.0.0.2
@@||disable_one^$dnsrewrite=127.0.0.1

|disable_all^$dnsrewrite=127.0.0.1
|disable_all^$dnsrewrite=127.0.0.2
@@||disable_all^$dnsrewrite

|disable_all_alt_syntax^$dnsrewrite=127.0.0.1
|disable_all_alt_syntax^$dnsrewrite=127.0.0.2
@@||disable_all_alt_syntax^$dnsrewrite=
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	ipv4p1 := net.IPv4(127, 0, 0, 1)
	ipv4p2 := net.IPv4(127, 0, 0, 2)
	ipv6p1 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv6p2 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	t.Run("short_v4", func(t *testing.T) {
		res, ok := dnsEngine.Match("short_v4")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v4_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match("short_v4_multiple")
		assert.True(t, ok)
		if assert.Equal(t, 2, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

			nr = res.DNSRewriteNetworkRules[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v4", func(t *testing.T) {
		res, ok := dnsEngine.Match("normal_v4")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v4_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match("normal_v4_multiple")
		assert.True(t, ok)
		if assert.Equal(t, 2, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

			nr = res.DNSRewriteNetworkRules[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v6", func(t *testing.T) {
		res, ok := dnsEngine.Match("short_v6")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v6_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match("short_v6_multiple")
		assert.True(t, ok)
		if assert.Equal(t, 2, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

			nr = res.DNSRewriteNetworkRules[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v6", func(t *testing.T) {
		res, ok := dnsEngine.Match("normal_v6")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v6_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match("normal_v6_multiple")
		assert.True(t, ok)
		if assert.Equal(t, 2, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

			nr = res.DNSRewriteNetworkRules[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("refused_host", func(t *testing.T) {
		res, ok := dnsEngine.Match("refused_host")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)
		}
	})

	t.Run("new_cname", func(t *testing.T) {
		res, ok := dnsEngine.Match("new_cname")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, "othercname", nr.DNSRewrite.NewCNAME)
		}
	})

	t.Run("new_txt", func(t *testing.T) {
		res, ok := dnsEngine.Match("new_txt")
		assert.True(t, ok)
		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeTXT, nr.DNSRewrite.RRType)
			assert.Equal(t, "new_txtcontent", nr.DNSRewrite.Value)
		}
	})

	t.Run("https_type", func(t *testing.T) {
		r := DNSRequest{
			Hostname: "https_type",
			DNSType:  dns.TypeHTTPS,
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)
		}

		r = DNSRequest{
			Hostname: "https_type",
			DNSType:  dns.TypeA,
		}

		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("priority", func(t *testing.T) {
		res, ok := dnsEngine.Match("priority")
		assert.True(t, ok)
		assert.Nil(t, res.NetworkRule)
		assert.Nil(t, res.HostRulesV4)
		assert.Nil(t, res.HostRulesV6)

		if assert.Equal(t, 1, len(res.DNSRewriteNetworkRules)) {
			nr := res.DNSRewriteNetworkRules[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("disable_one", func(t *testing.T) {
		res, ok := dnsEngine.Match("disable_one")
		assert.True(t, ok)

		var allowListCase *rules.NetworkRule
		if assert.Equal(t, 3, len(res.DNSRewriteNetworkRules)) {
			for _, r := range res.DNSRewriteNetworkRules {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			dr := allowListCase.DNSRewrite
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p1, dr.Value)
		}
	})

	t.Run("disable_all", func(t *testing.T) {
		res, ok := dnsEngine.Match("disable_all")
		assert.True(t, ok)

		var allowListCase *rules.NetworkRule
		if assert.Equal(t, 3, len(res.DNSRewriteNetworkRules)) {
			for _, r := range res.DNSRewriteNetworkRules {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
		}
	})

	t.Run("disable_all_alt_syntax", func(t *testing.T) {
		res, ok := dnsEngine.Match("disable_all_alt_syntax")
		assert.True(t, ok)

		var allowListCase *rules.NetworkRule
		if assert.Equal(t, 3, len(res.DNSRewriteNetworkRules)) {
			for _, r := range res.DNSRewriteNetworkRules {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
		}
	})
}
