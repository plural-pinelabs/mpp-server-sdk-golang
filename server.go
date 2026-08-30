package p3pserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
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

// GetOrder retrieves an order by its Pine Labs order ID.
func (s *Server) GetOrder(ctx context.Context, orderID string) (Order, error) {
	orderID = strings.TrimSpace(orderID)
	if orderID == "" {
		return Order{}, fmt.Errorf("order_id is required")
	}
	data, err := s.apiRequest(ctx, http.MethodGet, "/api/pay/v1/orders/"+pathEscape(orderID), nil, nil)
	if err != nil {
		return Order{}, err
	}
	return parseOrder(data), nil
}

// CreateRefund initiates a refund against a processed Pine Labs order.
func (s *Server) CreateRefund(ctx context.Context, orderID string, options CreateRefundOptions) (Refund, error) {
	orderID = strings.TrimSpace(orderID)
	if orderID == "" {
		return Refund{}, fmt.Errorf("order_id is required")
	}
	options.MerchantOrderReference = strings.TrimSpace(options.MerchantOrderReference)
	if options.MerchantOrderReference == "" {
		return Refund{}, fmt.Errorf("CreateRefundOptions: merchantOrderReference is required")
	}
	if options.OrderAmount.Value <= 0 {
		return Refund{}, fmt.Errorf("CreateRefundOptions: orderAmount.value must be a positive integer (paise)")
	}
	options.OrderAmount.Currency = strings.TrimSpace(options.OrderAmount.Currency)
	if options.OrderAmount.Currency == "" {
		return Refund{}, fmt.Errorf("CreateRefundOptions: orderAmount.currency is required")
	}

	headers := http.Header{
		"Request-ID":        {newID()},
		"Request-Timestamp": {time.Now().UTC().Format(time.RFC3339Nano)},
	}
	data, err := s.apiRequest(ctx, http.MethodPost, "/api/pay/v1/refunds/"+pathEscape(orderID), options, headers)
	if err != nil {
		return Refund{}, err
	}
	return parseRefund(data), nil
}
