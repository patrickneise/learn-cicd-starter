package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func authApiKeyHeader(key, value string) http.Header {
	header := http.Header{}
	header.Add(key, value)
	return header
}

func TestGetAPIKey(t *testing.T) {
	type Given struct {
		header http.Header
	}

	type Expected struct {
		apiKey string
		err    error
	}

	tests := map[string]struct {
		given    Given
		expected Expected
	}{
		"valid key": {
			Given{header: authApiKeyHeader("Authorization", "ApiKey thisisavalidapikey")},
			Expected{apiKey: "thisisavalidapikey", err: nil},
		},
		"missing key": {
			Given{header: authApiKeyHeader("Authorization", "ApiKey")},
			Expected{apiKey: "", err: ErrMalformedAuthorizationHeader},
		},
		"missing header": {
			Given{header: authApiKeyHeader("Auth", "ApiKey thisisavalidapikey")},
			Expected{apiKey: "", err: ErrNoAuthHeaderIncluded},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.given.header)
			if !errors.Is(err, tc.expected.err) {
				t.Fatalf("%s: expected: %v, got: %v", name, tc.expected.err, err)
			}
			if !reflect.DeepEqual(tc.expected.apiKey, got) {
				t.Fatalf("%s: expected: %v, got: %v", name, tc.expected.apiKey, got)
			}
		})
	}
}
