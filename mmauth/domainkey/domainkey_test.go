package domainkey

import (
	"testing"
)

func TestParseDomainKeyRecode(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedResult DomainKey
		expectedErr    error
	}{
		{
			name:  "Valid input 1",
			input: "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5jqnqaMgv8fFl8yQHDfPdU/7j0YvFza2YIMIYivVV/CaItZizlkY6emj9o6MZBK3RU9ni4BPCQ1do64+HhZHUanAPojZd0PsyusCBNBFU1wY6/xpcuoPf+Ru15UvLI2/o+9ElO4vF3l2YoTSOE5ljnBNd2EWihqmUQazEpu3PT1a7BbHZkW/7WdK5ipgU8+u/iyRai0DnrhgoiArzoDjFgm4TRJQGhD+EUOmnwFa3Xz5eQg50IigS7WKyHwF3HSZPzrkEFf5hIXYdoeIr6OqKg5sldONF/hY9voEITHZqtHOnrBlaBH2DTTI6uQH7Uc4JLv12xD6Gh1rlZy5zdMTwQIDAQAB",
			expectedResult: DomainKey{
				Version:       "DKIM1",
				HashAlgo:      []HashAlgo{HashAlgoSHA256},
				KeyType:       KeyTypeRSA,
				PublicKey:     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5jqnqaMgv8fFl8yQHDfPdU/7j0YvFza2YIMIYivVV/CaItZizlkY6emj9o6MZBK3RU9ni4BPCQ1do64+HhZHUanAPojZd0PsyusCBNBFU1wY6/xpcuoPf+Ru15UvLI2/o+9ElO4vF3l2YoTSOE5ljnBNd2EWihqmUQazEpu3PT1a7BbHZkW/7WdK5ipgU8+u/iyRai0DnrhgoiArzoDjFgm4TRJQGhD+EUOmnwFa3Xz5eQg50IigS7WKyHwF3HSZPzrkEFf5hIXYdoeIr6OqKg5sldONF/hY9voEITHZqtHOnrBlaBH2DTTI6uQH7Uc4JLv12xD6Gh1rlZy5zdMTwQIDAQAB",
				ServiceType:   []ServiceType{},
				SelectorFlags: []SelectorFlags{},
			},
			expectedErr: nil,
		},
		{
			name:  "Valid input 2",
			input: "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Lztpxs7yUxQEsbDFhjMc9kZVZu5P/COYEUIX4B39IL4SXAbv4viIlT9E6F6iZmTh1go7+9WQLywwgwjXMJx/Dz0RgMoPeyp5NRy4l320DPYibNqVMWa5iQ2WiImQC0en1O9uhLLvzaSZJ03fvGmCo9jMo0GwKzLNe14xMgn/px2L5N/3IKlKX4bqUAJTUt8L993ZlWzvgMnSFSt8B+euSKSrtAiopdy4r1yO4eN5goBASrGW0eLQc1lYouNvCrcTQpos4/GEAqiGzpqueJLmBfOO4clNvVvpPkvQs2BHw9I9LmIjaMxTNGxkGBRaP3utDiKXXqu1K+LRzl0HCNSdQIDAQAB",
			expectedResult: DomainKey{
				Version:       "",
				HashAlgo:      []HashAlgo{},
				KeyType:       KeyTypeRSA,
				PublicKey:     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Lztpxs7yUxQEsbDFhjMc9kZVZu5P/COYEUIX4B39IL4SXAbv4viIlT9E6F6iZmTh1go7+9WQLywwgwjXMJx/Dz0RgMoPeyp5NRy4l320DPYibNqVMWa5iQ2WiImQC0en1O9uhLLvzaSZJ03fvGmCo9jMo0GwKzLNe14xMgn/px2L5N/3IKlKX4bqUAJTUt8L993ZlWzvgMnSFSt8B+euSKSrtAiopdy4r1yO4eN5goBASrGW0eLQc1lYouNvCrcTQpos4/GEAqiGzpqueJLmBfOO4clNvVvpPkvQs2BHw9I9LmIjaMxTNGxkGBRaP3utDiKXXqu1K+LRzl0HCNSdQIDAQAB",
				ServiceType:   []ServiceType{},
				SelectorFlags: []SelectorFlags{},
			},
			expectedErr: nil,
		},
		{
			name:           "Invalid input 1",
			input:          "",
			expectedResult: DomainKey{},
			expectedErr:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualResult, actualErr := ParseDomainKeyRecode(tc.input)

			if actualResult.Version != tc.expectedResult.Version {
				t.Errorf("Expected version: %s, but got: %s", tc.expectedResult.Version, actualResult.Version)
			}

			if len(actualResult.HashAlgo) != len(tc.expectedResult.HashAlgo) {
				t.Errorf("Expected hash algo: %v, but got: %v", tc.expectedResult.HashAlgo, actualResult.HashAlgo)
			}

			if actualResult.KeyType != tc.expectedResult.KeyType {
				t.Errorf("Expected key type: %s, but got: %s", tc.expectedResult.KeyType, actualResult.KeyType)
			}

			if actualResult.PublicKey != tc.expectedResult.PublicKey {
				t.Errorf("Expected public key: %s, but got: %s", tc.expectedResult.PublicKey, actualResult.PublicKey)
			}

			if len(actualResult.ServiceType) != len(tc.expectedResult.ServiceType) {
				t.Errorf("Expected service type: %v, but got: %v", tc.expectedResult.ServiceType, actualResult.ServiceType)
			}

			if len(actualResult.SelectorFlags) != len(tc.expectedResult.SelectorFlags) {
				t.Errorf("Expected selector flags: %s, but got: %s", tc.expectedResult.SelectorFlags, actualResult.SelectorFlags)
			}

			if (tc.expectedErr == nil && actualErr != nil) || (tc.expectedErr != nil && actualErr == nil) || (tc.expectedErr != nil && actualErr != nil && tc.expectedErr.Error() != actualErr.Error()) {
				t.Errorf("Expected error: %v, but got: %v", tc.expectedErr, actualErr)
			}
		})
	}
}

func TestLookupDomainKey(t *testing.T) {
	testCases := []struct {
		name           string
		selector       string
		domain         string
		expectedResult DomainKey
		expectedErr    error
	}{
		{
			name:     "success",
			selector: "default",
			domain:   "masa23.jp",
			expectedResult: DomainKey{
				Version:       "DKIM1",
				HashAlgo:      []HashAlgo{HashAlgoSHA256},
				KeyType:       KeyTypeRSA,
				PublicKey:     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5jqnqaMgv8fFl8yQHDfPdU/7j0YvFza2YIMIYivVV/CaItZizlkY6emj9o6MZBK3RU9ni4BPCQ1do64+HhZHUanAPojZd0PsyusCBNBFU1wY6/xpcuoPf+Ru15UvLI2/o+9ElO4vF3l2YoTSOE5ljnBNd2EWihqmUQazEpu3PT1a7BbHZkW/7WdK5ipgU8+u/iyRai0DnrhgoiArzoDjFgm4TRJQGhD+EUOmnwFa3Xz5eQg50IigS7WKyHwF3HSZPzrkEFf5hIXYdoeIr6OqKg5sldONF/hY9voEITHZqtHOnrBlaBH2DTTI6uQH7Uc4JLv12xD6Gh1rlZy5zdMTwQIDAQAB",
				ServiceType:   []ServiceType{},
				SelectorFlags: []SelectorFlags{},
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualResult, actualErr := lookupDomainKey(tc.selector, tc.domain)

			if actualResult.Version != tc.expectedResult.Version {
				t.Errorf("Expected version: %s, but got: %s", tc.expectedResult.Version, actualResult.Version)
			}

			if len(actualResult.HashAlgo) != len(tc.expectedResult.HashAlgo) {
				t.Errorf("Expected hash algo: %v, but got: %v", tc.expectedResult.HashAlgo, actualResult.HashAlgo)
			}

			if actualResult.KeyType != tc.expectedResult.KeyType {
				t.Errorf("Expected key type: %s, but got: %s", tc.expectedResult.KeyType, actualResult.KeyType)
			}

			if actualResult.PublicKey != tc.expectedResult.PublicKey {
				t.Errorf("Expected public key: %s, but got: %s", tc.expectedResult.PublicKey, actualResult.PublicKey)
			}

			if len(actualResult.ServiceType) != len(tc.expectedResult.ServiceType) {
				t.Errorf("Expected service type: %v, but got: %v", tc.expectedResult.ServiceType, actualResult.ServiceType)
			}

			if len(actualResult.SelectorFlags) != len(tc.expectedResult.SelectorFlags) {
				t.Errorf("Expected selector flags: %s, but got: %s", tc.expectedResult.SelectorFlags, actualResult.SelectorFlags)
			}

			if (tc.expectedErr == nil && actualErr != nil) || (tc.expectedErr != nil && actualErr == nil) || (tc.expectedErr != nil && actualErr != nil && tc.expectedErr.Error() != actualErr.Error()) {
				t.Errorf("Expected error: %v, but got: %v", tc.expectedErr, actualErr)
			}
		})
	}
}
