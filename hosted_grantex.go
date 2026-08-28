package p3pserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultHostedGrantexBaseURL = "https://api.grantex.dev"

// HostedGrantexError describes a non-successful response from the hosted
// Grantex API.
type HostedGrantexError struct {
	Message    string
	Status     int
	Code       string
	Details    interface{}
	RequestID  string
	RetryAfter time.Duration
}

func (e *HostedGrantexError) Error() string { return e.Message }

// HostedGrantexClient is a small, typed client for the hosted Grantex APIs
// used by the MPP server SDK.
type HostedGrantexClient struct {
	apiKey     string
	baseURL    string
	http       HTTPDoer
	maxRetries int
}

func NewHostedGrantexClient(config HostedGrantexConfig) (*HostedGrantexClient, error) {
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, fmt.Errorf("HostedGrantexConfig: apiKey is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultHostedGrantexBaseURL
	}
	resolved, err := ResolveBaseURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("HostedGrantexConfig: baseUrl must use HTTPS (got: %s)", baseURL)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	retries := 3
	if config.MaxRetries != nil {
		retries = *config.MaxRetries
	}
	if retries < 0 {
		return nil, fmt.Errorf("HostedGrantexConfig: maxRetries must be non-negative")
	}
	return &HostedGrantexClient{apiKey: strings.TrimSpace(config.APIKey), baseURL: resolved, http: client, maxRetries: retries}, nil
}

func (c *HostedGrantexClient) CreateAuthorization(ctx context.Context, options GrantexAuthorizationOptions) (GrantexAuthorizationResult, error) {
	if strings.TrimSpace(options.AgentID) == "" {
		return GrantexAuthorizationResult{}, fmt.Errorf("GrantexAuthorizationOptions: agentId is required")
	}
	if strings.TrimSpace(options.UserID) == "" {
		return GrantexAuthorizationResult{}, fmt.Errorf("GrantexAuthorizationOptions: userId is required")
	}
	payload := map[string]interface{}{"agentId": options.AgentID, "principalId": options.UserID, "scopes": options.Scopes}
	setOptional(payload, "expiresIn", options.ExpiresIn)
	setOptionalString(payload, "redirectUri", options.RedirectURI)
	setOptionalString(payload, "codeChallenge", options.CodeChallenge)
	setOptionalString(payload, "codeChallengeMethod", options.CodeChallengeMethod)
	data, err := c.request(ctx, http.MethodPost, "/v1/authorize", payload)
	if err != nil {
		return GrantexAuthorizationResult{}, err
	}
	return GrantexAuthorizationResult{AuthRequestID: firstString(data, "authRequestId", "auth_request_id", "id", "requestId", "request_id"), ConsentURL: firstString(data, "consentUrl", "consent_url", "redirectUrl", "redirect_url", "url"), AgentID: firstString(data, "agentId", "agent_id"), PrincipalID: firstString(data, "principalId", "principal_id", "userId", "user_id"), Scopes: asStrings(data["scopes"]), ExpiresAt: firstString(data, "expiresAt", "expires_at"), Status: firstString(data, "status"), Raw: data}, nil
}

func (c *HostedGrantexClient) ExchangeCode(ctx context.Context, options GrantexExchangeCodeOptions) (GrantexExchangeCodeResult, error) {
	if strings.TrimSpace(options.Code) == "" {
		return GrantexExchangeCodeResult{}, fmt.Errorf("GrantexExchangeCodeOptions: code is required")
	}
	if strings.TrimSpace(options.AgentID) == "" {
		return GrantexExchangeCodeResult{}, fmt.Errorf("GrantexExchangeCodeOptions: agentId is required")
	}
	payload := map[string]interface{}{"code": options.Code, "agentId": options.AgentID}
	setOptionalString(payload, "codeVerifier", options.CodeVerifier)
	setOptionalString(payload, "credentialFormat", options.CredentialFormat)
	data, err := c.request(ctx, http.MethodPost, "/v1/token", payload)
	if err != nil {
		return GrantexExchangeCodeResult{}, err
	}
	return GrantexExchangeCodeResult{GrantToken: firstString(data, "grantToken", "grant_token", "accessToken", "access_token", "token"), GrantID: firstString(data, "grantId", "grant_id", "id"), RefreshToken: firstString(data, "refreshToken", "refresh_token"), Scopes: asStrings(data["scopes"]), ExpiresAt: firstString(data, "expiresAt", "expires_at"), Raw: data}, nil
}

func (c *HostedGrantexClient) AllocateBudget(ctx context.Context, options GrantexBudgetAllocationOptions) (GrantexBudgetAllocationResult, error) {
	if strings.TrimSpace(options.GrantID) == "" {
		return GrantexBudgetAllocationResult{}, fmt.Errorf("GrantexBudgetAllocationOptions: grantId is required")
	}
	if options.InitialBudget <= 0 {
		return GrantexBudgetAllocationResult{}, fmt.Errorf("GrantexBudgetAllocationOptions: initialBudget must be positive")
	}
	payload := map[string]interface{}{"grantId": options.GrantID, "initialBudget": options.InitialBudget}
	setOptionalString(payload, "currency", options.Currency)
	data, err := c.request(ctx, http.MethodPost, "/v1/budget/allocate", payload)
	if err != nil {
		return GrantexBudgetAllocationResult{}, err
	}
	return normalizeHostedBudget(data, options.GrantID), nil
}

func (c *HostedGrantexClient) DebitBudget(ctx context.Context, options GrantexBudgetDebitOptions) (GrantexBudgetDebitResult, error) {
	if strings.TrimSpace(options.GrantID) == "" {
		return GrantexBudgetDebitResult{}, fmt.Errorf("GrantexBudgetDebitOptions: grantId is required")
	}
	if options.Amount <= 0 {
		return GrantexBudgetDebitResult{}, fmt.Errorf("GrantexBudgetDebitOptions: amount must be positive")
	}
	payload := map[string]interface{}{"grantId": options.GrantID, "amount": options.Amount}
	setOptionalString(payload, "description", options.Description)
	if options.Metadata != nil {
		payload["metadata"] = options.Metadata
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/budget/debit", payload)
	if err != nil {
		return GrantexBudgetDebitResult{}, err
	}
	return GrantexBudgetDebitResult{GrantID: firstNonEmpty(firstString(data, "grantId", "grant_id"), options.GrantID), Remaining: firstFloat(data, "remaining", "remainingBudget", "remaining_budget"), TransactionID: firstString(data, "transactionId", "transaction_id", "id"), Raw: data}, nil
}

func (c *HostedGrantexClient) GetBudgetBalance(ctx context.Context, grantID string) (GrantexBudgetBalanceResult, error) {
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return GrantexBudgetBalanceResult{}, fmt.Errorf("grantId is required")
	}
	data, err := c.request(ctx, http.MethodGet, "/v1/budget/balance/"+url.PathEscape(grantID), nil)
	if err != nil {
		return GrantexBudgetBalanceResult{}, err
	}
	return normalizeHostedBudget(data, grantID), nil
}

func (c *HostedGrantexClient) ListBudgetTransactions(ctx context.Context, grantID string, options *GrantexBudgetTransactionsOptions) (GrantexBudgetTransactionsResult, error) {
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return GrantexBudgetTransactionsResult{}, fmt.Errorf("grantId is required")
	}
	query := url.Values{}
	if options != nil {
		if options.Limit > 0 {
			query.Set("limit", fmt.Sprintf("%d", options.Limit))
		}
		if options.Cursor != "" {
			query.Set("cursor", options.Cursor)
		}
	}
	path := "/v1/budget/transactions/" + url.PathEscape(grantID)
	if queryString := query.Encode(); queryString != "" {
		path += "?" + queryString
	}
	data, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return GrantexBudgetTransactionsResult{}, err
	}
	items, _ := data["transactions"].([]interface{})
	transactions := make([]GrantexBudgetTransaction, 0, len(items))
	for _, item := range items {
		entry := asMap(item)
		transactions = append(transactions, GrantexBudgetTransaction{ID: firstString(entry, "id", "transactionId", "transaction_id"), GrantID: firstNonEmpty(firstString(entry, "grantId", "grant_id"), grantID), Amount: firstFloat(entry, "amount"), Description: firstString(entry, "description"), BalanceAfter: firstFloat(entry, "balanceAfter", "balance_after"), CreatedAt: firstString(entry, "createdAt", "created_at"), Raw: entry})
	}
	return GrantexBudgetTransactionsResult{Transactions: transactions, Total: asInt(data["total"]), Raw: data}, nil
}

func (c *HostedGrantexClient) request(ctx context.Context, method, path string, payload interface{}) (map[string]interface{}, error) {
	var raw []byte
	var err error
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	factory := func() (*http.Request, error) {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(raw)
		}
		req, requestErr := http.NewRequest(method, c.baseURL+path, body)
		if requestErr == nil {
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
			req.Header.Set("User-Agent", "p3p-server-sdk-go/0.1.0")
			if payload != nil {
				req.Header.Set("Content-Type", "application/json")
			}
		}
		return req, requestErr
	}
	resp, err := doWithRetry(ctx, c.http, factory, c.maxRetries, 500*time.Millisecond)
	if err != nil {
		return nil, &HostedGrantexError{Message: err.Error(), Details: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &HostedGrantexError{Message: err.Error(), Status: resp.StatusCode, Details: err}
	}
	var data map[string]interface{}
	if len(body) > 0 && json.Unmarshal(body, &data) != nil {
		data = map[string]interface{}{"body": string(body)}
	}
	if resp.StatusCode >= 400 {
		message := firstNonEmpty(firstString(data, "message"), firstString(data, "error"), fmt.Sprintf("HTTP %d", resp.StatusCode))
		code := firstString(data, "code")
		if nested := asMap(data["error"]); len(nested) > 0 {
			message = firstNonEmpty(firstString(nested, "message"), message)
			code = firstNonEmpty(firstString(nested, "code"), code)
		}
		return nil, &HostedGrantexError{Message: message, Status: resp.StatusCode, Code: code, Details: data, RequestID: resp.Header.Get("X-Request-ID"), RetryAfter: retryDelay(resp.Header.Get("Retry-After"), 0)}
	}
	return data, nil
}

func normalizeHostedBudget(data map[string]interface{}, grantID string) GrantexBudgetAllocationResult {
	return GrantexBudgetAllocationResult{ID: firstString(data, "id", "budgetId", "budget_id"), GrantID: firstNonEmpty(firstString(data, "grantId", "grant_id"), grantID), InitialBudget: firstFloat(data, "initialBudget", "initial_budget"), RemainingBudget: firstFloat(data, "remainingBudget", "remaining_budget"), Currency: firstNonEmpty(firstString(data, "currency"), "INR"), CreatedAt: firstString(data, "createdAt", "created_at"), Raw: data}
}

func firstFloat(data map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			return asFloat(value)
		}
	}
	return 0
}

func setOptional(payload map[string]interface{}, key string, value interface{}) {
	if value != nil {
		payload[key] = value
	}
}

func setOptionalString(payload map[string]interface{}, key, value string) {
	if strings.TrimSpace(value) != "" {
		payload[key] = value
	}
}

func (s *Server) requireHostedGrantex() (*HostedGrantexClient, error) {
	if s.hosted == nil {
		return nil, fmt.Errorf("PineLabsOnlineServerConfig: grantex.hosted is required")
	}
	return s.hosted, nil
}

func (s *Server) CreateGrantexAuthorization(ctx context.Context, options GrantexAuthorizationOptions) (GrantexAuthorizationResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexAuthorizationResult{}, err
	}
	return client.CreateAuthorization(ctx, options)
}

func (s *Server) ExchangeGrantexCode(ctx context.Context, options GrantexExchangeCodeOptions) (GrantexExchangeCodeResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexExchangeCodeResult{}, err
	}
	return client.ExchangeCode(ctx, options)
}

func (s *Server) AllocateGrantexBudget(ctx context.Context, options GrantexBudgetAllocationOptions) (GrantexBudgetAllocationResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexBudgetAllocationResult{}, err
	}
	return client.AllocateBudget(ctx, options)
}

func (s *Server) DebitGrantexBudget(ctx context.Context, options GrantexBudgetDebitOptions) (GrantexBudgetDebitResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexBudgetDebitResult{}, err
	}
	return client.DebitBudget(ctx, options)
}

func (s *Server) GetGrantexBudgetBalance(ctx context.Context, grantID string) (GrantexBudgetBalanceResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexBudgetBalanceResult{}, err
	}
	return client.GetBudgetBalance(ctx, grantID)
}

func (s *Server) ListGrantexBudgetTransactions(ctx context.Context, grantID string, options *GrantexBudgetTransactionsOptions) (GrantexBudgetTransactionsResult, error) {
	client, err := s.requireHostedGrantex()
	if err != nil {
		return GrantexBudgetTransactionsResult{}, err
	}
	return client.ListBudgetTransactions(ctx, grantID, options)
}
