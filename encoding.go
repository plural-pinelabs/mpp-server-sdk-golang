package p3pserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func EncodeBase64URL(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
func DecodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
}
func EncodeJSON(value interface{}) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return EncodeBase64URL(raw), nil
}
func DecodeJSON(value string, target interface{}) error {
	raw, err := DecodeBase64URL(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode base64url JSON: %w", err)
	}
	return nil
}
