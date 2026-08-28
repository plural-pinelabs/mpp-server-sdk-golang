package p3pserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

type authManager struct {
	config  Config
	http    HTTPDoer
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (a *authManager) accessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Now().Before(a.expires.Add(-time.Minute)) {
		return a.token, nil
	}
	raw, _ := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": a.config.ClientID, "client_secret": a.config.ClientSecret})
	factory := func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, a.config.Env+"/api/auth/v1/token", bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}
	resp, err := doWithRetry(ctx, a.http, factory, *a.config.MaxRetries, a.config.InitialRetryDelay)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", errorFromResponse(resp.StatusCode, body)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	data := asMap(envelope["data"])
	if len(data) == 0 {
		data = envelope
	}
	token := firstString(data, "access_token")
	if token == "" {
		return "", &Error{Code: "MPP_AUTHENTICATION_FAILED", Message: "Token exchange response missing access_token", HTTPStatus: resp.StatusCode}
	}
	expires := time.Now().Add(time.Duration(asInt(data["expires_in"])) * time.Second)
	if asInt(data["expires_in"]) == 0 {
		expires = time.Now().Add(time.Hour)
	}
	if value := firstString(data, "expires_at"); value != "" {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, value); parseErr == nil {
			expires = parsed
		}
	}
	a.token, a.expires = token, expires
	return token, nil
}
func (a *authManager) invalidate() { a.mu.Lock(); a.token = ""; a.expires = time.Time{}; a.mu.Unlock() }
