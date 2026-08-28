package p3pserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type Server struct {
	config Config
	http   HTTPDoer
	auth   *authManager
	hosted *HostedGrantexClient
}

func New(config Config) (*Server, error) {
	resolved, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	client := resolved.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: resolved.RequestTimeout}
	}
	server := &Server{config: resolved, http: client}
	server.auth = &authManager{config: resolved, http: client}
	if resolved.Grantex != nil && resolved.Grantex.Hosted != nil {
		hosted, hostedErr := NewHostedGrantexClient(*resolved.Grantex.Hosted)
		if hostedErr != nil {
			return nil, hostedErr
		}
		server.hosted = hosted
	}
	return server, nil
}
func (s *Server) Config() Config { return s.config }
func (s *Server) GetDebitStatus(ctx context.Context, key string) (CaptureResult, error) {
	return s.getDebitStatus(ctx, key)
}
func (s *Server) CreateMandate(ctx context.Context, options CreateMandateOptions) (Mandate, error) {
	data, err := s.createPreAuthorizationRequest(ctx, options)
	if err != nil {
		return Mandate{}, err
	}
	return parseMandate(data), nil
}
func (s *Server) CreatePreAuthorization(ctx context.Context, options CreatePreAuthorizationOptions) (PreAuthorization, error) {
	data, err := s.createPreAuthorizationRequest(ctx, options)
	if err != nil {
		return PreAuthorization{}, err
	}
	return parsePreAuthorization(data), nil
}
func (s *Server) GetMandate(ctx context.Context, id string) (Mandate, error) {
	if strings.TrimSpace(id) == "" {
		return Mandate{}, fmt.Errorf("mandate_id is required")
	}
	data, err := s.apiRequest(ctx, http.MethodGet, "/mpp/v1/authorization/"+pathEscape(id), nil, nil)
	if err != nil {
		return Mandate{}, err
	}
	return parseMandate(data), nil
}
