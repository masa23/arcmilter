package arc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/masa23/arcmilter/mmauth/internal/header"
)

// ARC-Authentication-Results の構造体
// 最低限の情報を保持する
type ARCAuthenticationResults struct {
	InstanceNumber int    // i
	AuthServId     string // Atuhentication Server Domain
	Results        []string
	raw            string
}

func (aar *ARCAuthenticationResults) Raw() string {
	if aar.raw == "" {
		return aar.String()
	}
	return aar.raw
}

// ARC-Authentication-Results の文字列化
// ヘッダ名は含まない
func (aar ARCAuthenticationResults) String() string {
	header := fmt.Sprintf("i=%d; %s;", aar.InstanceNumber, aar.AuthServId)
	for _, result := range aar.Results {
		header += fmt.Sprintf("\r\n        %s;", result)
	}
	return header
}

// ARC-Authentication-Results のパース
func ParseARCAuthenticationResults(s string) (*ARCAuthenticationResults, error) {
	result := &ARCAuthenticationResults{}
	result.raw = s

	// ヘッダと値に分割
	k, v := header.ParseHeaderField(s)
	if !strings.EqualFold(k, "arc-authentication-results") {
		return nil, fmt.Errorf("invalid header field")
	}
	fields := strings.Split(v, ";")

	for i, field := range fields {
		keyValue := strings.SplitN(strings.TrimSpace(field), "=", 2)

		if i == 1 { // authserv-id は通常インスタンス番号の直後に位置します
			result.AuthServId = strings.TrimSpace(keyValue[0])
			continue
		}

		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		switch key {
		case "i":
			instanceNumber, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid instance number")
			}
			result.InstanceNumber = instanceNumber
		default:
			result.Results = append(result.Results, fmt.Sprintf("%s=%s", key, value))
		}
	}

	return result, nil
}
