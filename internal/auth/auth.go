package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
var ErrMalformedAuthorizationHeader = errors.New("malformed authorization header")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("%q: %w", headers, ErrNoAuthHeaderIncluded)
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", fmt.Errorf("%q: %w", headers, ErrMalformedAuthorizationHeader)
	}

	return splitAuth[1], nil
}
