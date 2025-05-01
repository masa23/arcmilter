package dmarc

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
)

func assertDMARCEqual(t *testing.T, got, expected DMARC) {
	t.Helper()
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("DMARC mismatch:\nExpected: %+v\nGot:      %+v", expected, got)
	}
}

func assertErrorEqual(t *testing.T, got, expected error) {
	t.Helper()
	if !errors.Is(got, expected) {
		t.Errorf("Expected error: %v, but got: %v", expected, got)
	}
}

func TestParseDMARCRecord(t *testing.T) {
	testCases := []struct {
		raw      string
		expected DMARC
	}{
		{
			raw: "v=DMARC1; p=none; rua=mailto:agg@example.com; ruf=mailto:for@example.com; fo=1:d:s; adkim=s; aspf=r; pct=50; ri=3600; sp=quarantine;",
			expected: DMARC{
				Version:            "DMARC1",
				Policy:             PolicyNone,
				SubdomainPolicy:    PolicyQuarantine,
				AggregateReportURI: []string{"mailto:agg@example.com"},
				ForensicReportURI:  []string{"mailto:for@example.com"},
				FailureOptions:     []FailureOption{"1", "d", "s"},
				AlignmentDKIM:      AlignmentStrict,
				AlignmentSPF:       AlignmentRelaxed,
				Percent:            50,
				ReportInterval:     3600,
				raw:                "v=DMARC1; p=none; rua=mailto:agg@example.com; ruf=mailto:for@example.com; fo=1:d:s; adkim=s; aspf=r; pct=50; ri=3600; sp=quarantine;",
			},
		},
		{
			raw: "v=DMARC1; p=reject; adkim=r; aspf=s;",
			expected: DMARC{
				Version:       "DMARC1",
				Policy:        PolicyReject,
				AlignmentDKIM: AlignmentRelaxed,
				AlignmentSPF:  AlignmentStrict,
				raw:           "v=DMARC1; p=reject; adkim=r; aspf=s;",
			},
		},
		{
			raw: "v=DMARC1; p=quarantine; pct=100; ri=86400;",
			expected: DMARC{
				Version:        "DMARC1",
				Policy:         PolicyQuarantine,
				Percent:        100,
				ReportInterval: 86400,
				raw:            "v=DMARC1; p=quarantine; pct=100; ri=86400;",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Parse: %s", tc.raw), func(t *testing.T) {
			got, err := ParseDMARCRecord(tc.raw)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			assertDMARCEqual(t, got, tc.expected)
		})
	}
}

func TestLookupDMARCRecord(t *testing.T) {
	testCases := []struct {
		domain   string
		want     DMARC
		wantErr  error
		resolver TXTLookupFunc
	}{
		{
			domain: "masa23.jp",
			want: DMARC{
				Version:            "DMARC1",
				Policy:             "reject",
				AggregateReportURI: []string{"mailto:abuse@masa23.jp"},
				ForensicReportURI:  []string{"mailto:abuse@masa23.jp"},
				raw:                "v=DMARC1; p=reject; rua=mailto:abuse@masa23.jp; ruf=mailto:abuse@masa23.jp;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.masa23.jp" {
					return []string{"v=DMARC1; p=reject; rua=mailto:abuse@masa23.jp; ruf=mailto:abuse@masa23.jp;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain:  "example.jp",
			want:    DMARC{},
			wantErr: ErrNoRecordFound,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Lookup: %s", tc.domain), func(t *testing.T) {
			got, err := LookupDMARCRecord(tc.domain, nil)
			assertErrorEqual(t, err, tc.wantErr)
			assertDMARCEqual(t, got, tc.want)
		})
	}
}

func TestLookupDMARCRecordWithSubdomainFallback(t *testing.T) {
	testCases := []struct {
		domain   string
		want     DMARC
		wantErr  error
		resolver TXTLookupFunc
	}{
		{
			domain: "masa23.jp",
			want: DMARC{
				Version:            "DMARC1",
				Policy:             "reject",
				AggregateReportURI: []string{"mailto:abuse@masa23.jp"},
				ForensicReportURI:  []string{"mailto:abuse@masa23.jp"},
				raw:                "v=DMARC1; p=reject; rua=mailto:abuse@masa23.jp; ruf=mailto:abuse@masa23.jp;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.masa23.jp" {
					return []string{"v=DMARC1; p=reject; rua=mailto:abuse@masa23.jp; ruf=mailto:abuse@masa23.jp;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain:  "sub.masa23.jp",
			want:    DMARC{},
			wantErr: nil, // inherits via fallback or explicitly empty
		},
		{
			domain:  "example.jp",
			want:    DMARC{},
			wantErr: ErrNoRecordFound,
		},
		{
			domain:  "sub.example.jp",
			want:    DMARC{},
			wantErr: ErrNoRecordFound,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("LookupWithFallback: %s", tc.domain), func(t *testing.T) {
			got, err := LookupDMARCWithSubdomainFallback(tc.domain, tc.resolver)
			assertErrorEqual(t, err, tc.wantErr)
			assertDMARCEqual(t, got, tc.want)
		})
	}
}
