package dmarc

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type TXTLookupFunc func(name string) ([]string, error)

var (
	ErrNoRecordFound   = errors.New("no record found")
	ErrDNSLookupFailed = errors.New("dns lookup failed")
)

type AlignmentMode string

const (
	AlignmentRelaxed AlignmentMode = "r" // relaxed
	AlignmentStrict  AlignmentMode = "s" // strict
)

type FailureOption string

const (
	FailureAllFail  FailureOption = "0" // Report when all mechanisms fail with no aligned pass
	FailureAnyFail  FailureOption = "1" // Report when any mechanism fails to produce aligned pass
	FailureDKIMOnly FailureOption = "d" // Report when a DKIM signature fails evaluation
	FailureSPFOnly  FailureOption = "s" // Report when SPF evaluation fails
)

type PolicyType string

const (
	PolicyNone       PolicyType = "none"
	PolicyQuarantine PolicyType = "quarantine"
	PolicyReject     PolicyType = "reject"
)

type DMARC struct {
	AggregateReportURI []string        // rua Aggregate report URIs
	AlignmentDKIM      AlignmentMode   // adkim DKIM alignment mode (r or s)
	AlignmentSPF       AlignmentMode   // aspf SPF alignment mode (r or s)
	ForensicReportURI  []string        // ruf Forensic report URIs (optional, deprecated)
	FailureOptions     []FailureOption // fo Forensic reporting options (optional, deprecated)
	Percent            int             // pct Percentage of messages to apply policy to
	Policy             PolicyType      // p Policy (none, quarantine, reject)
	ReportInterval     uint32          // ri Interval for aggregate reports (seconds)
	SubdomainPolicy    PolicyType      // sp Subdomain policy
	Version            string          // v DMARC version, must be "DMARC1"
	raw                string          // raw record
}

func getOrganizationalDomain(domain string) (string, error) {
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", fmt.Errorf("failed to get organizational domain: %w", err)
	}
	return orgDomain, nil
}

func LookupDMARCWithSubdomainFallback(domain string, resolver TXTLookupFunc) (DMARC, error) {
	// Try direct DMARC lookup
	d, err := LookupDMARCRecord(domain, resolver)
	if err == nil {
		return d, nil
	}
	if !errors.Is(err, ErrNoRecordFound) {
		return DMARC{}, err
	}

	// Try fallback to organizational domain
	orgDomain, err := getOrganizationalDomain(domain)
	if err != nil {
		return DMARC{}, err
	}
	if orgDomain == domain {
		return DMARC{}, ErrNoRecordFound
	}

	// Recursive lookup on organizational domain
	d, err = LookupDMARCWithSubdomainFallback(orgDomain, resolver)
	if err != nil {
		return DMARC{}, err
	}

	// Only use parent record if sp= is defined
	if d.SubdomainPolicy == "" {
		return DMARC{}, nil
	}
	return d, nil
}

func LookupDMARCRecord(domain string, resolver TXTLookupFunc) (DMARC, error) {
	if resolver == nil {
		resolver = net.LookupTXT
	}
	query := fmt.Sprintf("_dmarc.%s", domain)
	res, err := resolver(query)
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsNotFound {
			return DMARC{}, ErrNoRecordFound
		}
	} else if err != nil {
		return DMARC{}, ErrDNSLookupFailed
	}
	for _, v := range res {
		d, err := ParseDMARCRecord(v)
		if err != nil {
			return DMARC{}, err
		}
		if d.Policy != "" {
			return d, nil
		}
	}
	return DMARC{}, ErrNoRecordFound
}

func ParseDMARCRecord(raw string) (DMARC, error) {
	var d DMARC
	d.raw = raw

	pairs := strings.Split(raw, ";")
	for _, pair := range pairs {
		k, v, _ := strings.Cut(pair, "=")
		switch strings.TrimSpace(k) {
		case "v":
			d.Version = strings.TrimSpace(v)
			if d.Version != "DMARC1" {
				return DMARC{}, fmt.Errorf("invalid version: %s", d.Version)
			}
		case "rua":
			d.AggregateReportURI = strings.Split(strings.TrimSpace(v), ",")
		case "adkim":
			d.AlignmentDKIM = AlignmentMode(strings.TrimSpace(v))
			if d.AlignmentDKIM != AlignmentRelaxed && d.AlignmentDKIM != AlignmentStrict {
				return DMARC{}, fmt.Errorf("invalid adkim value: %s", d.AlignmentDKIM)
			}
		case "aspf":
			d.AlignmentSPF = AlignmentMode(strings.TrimSpace(v))
			if d.AlignmentSPF != AlignmentRelaxed && d.AlignmentSPF != AlignmentStrict {
				return DMARC{}, fmt.Errorf("invalid aspf value: %s", d.AlignmentSPF)
			}
		case "ruf":
			d.ForensicReportURI = strings.Split(strings.TrimSpace(v), ",")
		case "fo":
			fo := strings.Split(strings.TrimSpace(v), ":")
			for _, f := range fo {
				switch FailureOption(f) {
				case FailureAllFail, FailureAnyFail, FailureDKIMOnly, FailureSPFOnly:
					d.FailureOptions = append(d.FailureOptions, FailureOption(f))
				default:
					return DMARC{}, fmt.Errorf("invalid fo value: %s", f)
				}
			}
		case "pct":
			pct, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return DMARC{}, fmt.Errorf("invalid pct value: %s", v)
			}
			if pct < 0 || pct > 100 {
				return DMARC{}, fmt.Errorf("pct value out of range: %d", pct)
			}
			d.Percent = pct
		case "p":
			d.Policy = PolicyType(strings.TrimSpace(v))
			if d.Policy != PolicyNone && d.Policy != PolicyQuarantine && d.Policy != PolicyReject {
				return DMARC{}, fmt.Errorf("invalid p value: %s", d.Policy)
			}
		case "ri":
			ri, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return DMARC{}, fmt.Errorf("invalid ri value: %s", v)
			}
			if ri < 0 {
				return DMARC{}, fmt.Errorf("ri value out of range: %d", ri)
			}
			d.ReportInterval = uint32(ri)
		case "sp":
			d.SubdomainPolicy = PolicyType(strings.TrimSpace(v))
			if d.SubdomainPolicy != PolicyNone && d.SubdomainPolicy != PolicyQuarantine && d.SubdomainPolicy != PolicyReject {
				return DMARC{}, fmt.Errorf("invalid sp value: %s", d.SubdomainPolicy)
			}
		}
	}

	if d.Version == "" {
		return DMARC{}, fmt.Errorf("missing version tag")
	}

	return d, nil
}
