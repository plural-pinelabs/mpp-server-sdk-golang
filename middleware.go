package p3pserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const MaxTransactionScopePrefix = "mpp:payment:max_txn_paise:"

// ChargeOptionsResolver derives the protected resource and charge from an
// incoming request.
type ChargeOptionsResolver func(*http.Request) (ChargeOptions, error)

// DecidePayment is the framework-neutral payment workflow. It returns a
// challenge, a rejection, a pending response, or permission to call the
// protected handler.
func (s *Server) DecidePayment(ctx context.Context, credentialHeader, authorizationHeader, grantexToken string, options ChargeOptions) Decision {
	grantResult := s.verifyGrantex(ctx, grantexToken)
	if decision := s.decideGrant(grantexToken, grantResult); decision != nil {
		return *decision
	}
	if decision := s.decideTransactionCap(options, grantResult); decision != nil {
		return *decision
	}

	header := credentialHeader
	if header == "" {
		header = authorizationHeader
	}
	if !strings.HasPrefix(header, "Payment ") {
		if decision := s.checkHostedBudget(ctx, options, grantResult); decision != nil {
			return *decision
		}
		return s.challengeDecision(options, "challenge", "")
	}

	verification := s.VerifyCredential(header)
	if !verification.Valid || verification.Credential == nil {
		return s.challengeDecision(options, "invalid", verification.Error)
	}
	credential := verification.Credential
	capture, err := s.Capture(ctx, CaptureOptions{
		Token:                    credential.Payload.Token,
		Amount:                   options.Amount,
		PaymentMethod:            credential.Payload.PaymentMethod,
		Description:              options.Description,
		MerchantOrderReference:   options.MerchantOrderReference,
		Metadata:                 stringifyMetadata(options.Metadata),
		PaymentMethodReferenceID: credential.Payload.PaymentMethodReferenceID,
		CustomerReference:        credential.Payload.CustomerReference,
		MobileNumber:             credential.Payload.MobileNumber,
		ChallengeID:              credential.Challenge.ID,
	})
	if err != nil {
		status, code, message := http.StatusBadGateway, "CAPTURE_FAILED", "Capture failed"
		if captureError, ok := err.(*CaptureError); ok {
			message = captureError.Message
			if captureError.Cause != nil {
				code = captureError.Cause.Code
				if captureError.Cause.HTTPStatus < 500 && captureError.Cause.HTTPStatus >= 400 {
					status = captureError.Cause.HTTPStatus
				}
			}
		}
		action := "error"
		if status < 500 {
			action = "failed"
		}
		return Decision{Action: action, Status: status, Headers: http.Header{"Content-Type": {"application/json"}}, ProblemDetails: map[string]interface{}{"code": code, "message": message}, GrantResult: grantResult}
	}
	if capture.Pending || IsPendingDebitStatus(capture.Status) {
		body := map[string]interface{}{"status": firstNonEmpty(capture.Status, "PENDING"), "pending": true, "message": firstNonEmpty(capture.Message, "Payment accepted and still processing"), "idempotencyKey": capture.IdempotencyKey}
		return Decision{Action: "pending", Status: http.StatusAccepted, Headers: http.Header{"Content-Type": {"application/json"}}, ProblemDetails: body, PendingBody: body, CaptureResult: &capture, Credential: credential, GrantResult: grantResult}
	}
	s.debitHostedBudget(ctx, options, grantResult)
	receipt, receiptErr := s.BuildReceiptHeader(capture, credential.Challenge.ID, s.config.PaymentGateway, credential.Payload.PaymentMethod)
	if receiptErr != nil {
		return Decision{Action: "error", Status: http.StatusBadGateway, Headers: http.Header{"Content-Type": {"application/json"}}, ProblemDetails: map[string]interface{}{"code": "RECEIPT_FAILED", "message": receiptErr.Error()}, CaptureResult: &capture, Credential: credential, GrantResult: grantResult}
	}
	return Decision{Action: "proceed", Status: http.StatusOK, Headers: http.Header{"Payment-Receipt": {receipt}}, CaptureResult: &capture, Credential: credential, ReceiptHeader: receipt, GrantResult: grantResult}
}

func (s *Server) challengeDecision(options ChargeOptions, action, verificationError string) Decision {
	challenge, err := s.GenerateChallenge(options)
	if err != nil {
		return Decision{Action: "error", Status: http.StatusInternalServerError, Headers: http.Header{"Content-Type": {"application/json"}}, ProblemDetails: map[string]interface{}{"code": "CHALLENGE_FAILED", "message": err.Error()}}
	}
	problem := map[string]interface{}{"type": challenge.ProblemDetails.Type, "title": challenge.ProblemDetails.Title, "status": challenge.ProblemDetails.Status, "detail": challenge.ProblemDetails.Detail, "challengeId": challenge.ProblemDetails.ChallengeID}
	if action == "invalid" {
		problem["type"] = strings.Replace(challenge.ProblemDetails.Type, "payment-required", "payment-invalid", 1)
		problem["title"] = "Invalid Payment Credential"
		problem["detail"] = firstNonEmpty(verificationError, "The payment credential could not be verified.")
	}
	return Decision{Action: action, Status: http.StatusPaymentRequired, Headers: http.Header{"WWW-Authenticate": {"Payment " + challenge.Encoded}, "Content-Type": {"application/problem+json"}, "Cache-Control": {"no-store"}}, ProblemDetails: problem, ChallengeResult: &challenge}
}

func (s *Server) verifyGrantex(ctx context.Context, token string) *GrantexVerificationResult {
	if s.config.Grantex == nil || strings.TrimSpace(token) == "" {
		return nil
	}
	var result GrantexVerificationResult
	if s.config.Grantex.Verifier != nil {
		result = postValidateGrantResult(s.config.Grantex.Verifier.Verify(ctx, token), *s.config.Grantex)
	} else {
		result = NewGrantTokenVerifier(*s.config.Grantex, s.http).Verify(ctx, token)
	}
	return &result
}

func (s *Server) decideGrant(token string, result *GrantexVerificationResult) *Decision {
	config := s.config.Grantex
	if config == nil {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		if !config.EnforceGrant {
			return nil
		}
		result = &GrantexVerificationResult{Error: "Missing grant token"}
		return &Decision{Action: "grant_required", Status: http.StatusForbidden, Headers: noStoreProblemHeaders(), ProblemDetails: map[string]interface{}{"type": "urn:ietf:rfc:9725:error:grant-required", "title": "Grant Token Required", "status": http.StatusForbidden, "detail": "A valid Grantex grant token is required in the " + GrantexTokenHeader + " header."}, GrantResult: result}
	}
	if result == nil || result.Valid || !config.EnforceGrant {
		return nil
	}
	if s.config.Logger != nil {
		s.config.Logger.Error("Grantex grant verification failed", map[string]interface{}{"error": result.Error})
	}
	return &Decision{Action: "grant_invalid", Status: http.StatusForbidden, Headers: noStoreProblemHeaders(), ProblemDetails: map[string]interface{}{"type": "urn:ietf:rfc:9725:error:grant-invalid", "title": "Invalid Grant Token", "status": http.StatusForbidden, "detail": "The grant token could not be verified."}, GrantResult: result}
}

func (s *Server) decideTransactionCap(options ChargeOptions, result *GrantexVerificationResult) *Decision {
	if s.config.Grantex == nil || !s.config.Grantex.EnforceGrant || result == nil || !result.Valid || result.Grant == nil {
		return nil
	}
	cap, ok := maxTransactionPaise(result.Grant.Scopes)
	if !ok || options.Amount.Value <= cap {
		return nil
	}
	invalid := &GrantexVerificationResult{Grant: result.Grant, Error: "Grantex per-transaction cap exceeded"}
	return &Decision{Action: "grant_invalid", Status: http.StatusForbidden, Headers: noStoreProblemHeaders(), ProblemDetails: map[string]interface{}{"type": "urn:ietf:rfc:9725:error:transaction-limit-exceeded", "title": "Transaction Limit Exceeded", "status": http.StatusForbidden, "detail": fmt.Sprintf("The charge amount %d exceeds the Grantex per-transaction cap %d.", options.Amount.Value, cap)}, GrantResult: invalid}
}

func (s *Server) checkHostedBudget(ctx context.Context, options ChargeOptions, result *GrantexVerificationResult) *Decision {
	if !s.shouldUseHostedBudget(result) {
		return nil
	}
	balance, err := s.hosted.GetBudgetBalance(ctx, result.Grant.GrantID)
	if err != nil {
		return s.budgetRejected(result.Grant, "The Grantex grant budget could not be checked.", err.Error())
	}
	remainingPaise := int64(balance.RemainingBudget*100 + 0.5)
	if remainingPaise >= options.Amount.Value {
		return nil
	}
	detail := fmt.Sprintf("The Grantex grant budget has %d paise remaining, which is less than the charge amount %d paise.", remainingPaise, options.Amount.Value)
	return s.budgetRejected(result.Grant, detail, "Grantex grant budget exceeded")
}

func (s *Server) budgetRejected(grant *GrantexGrant, detail, reason string) *Decision {
	result := &GrantexVerificationResult{Grant: grant, Error: reason}
	return &Decision{Action: "grant_invalid", Status: http.StatusForbidden, Headers: noStoreProblemHeaders(), ProblemDetails: map[string]interface{}{"type": "urn:ietf:rfc:9725:error:budget-exceeded", "title": "Grant Budget Exceeded", "status": http.StatusForbidden, "detail": detail}, GrantResult: result}
}

func (s *Server) debitHostedBudget(ctx context.Context, options ChargeOptions, result *GrantexVerificationResult) {
	if !s.shouldUseHostedBudget(result) {
		return
	}
	metadata := map[string]interface{}{"resource": options.Resource, "currency": options.Amount.Currency}
	for key, value := range options.Metadata {
		metadata[key] = value
	}
	_, err := s.hosted.DebitBudget(ctx, GrantexBudgetDebitOptions{GrantID: result.Grant.GrantID, Amount: float64(options.Amount.Value) / 100, Description: firstNonEmpty(options.Description, "P3P payment capture"), Metadata: metadata})
	if err != nil && s.config.Logger != nil {
		s.config.Logger.Error("Grantex budget debit failed after successful capture", map[string]interface{}{"error": err.Error()})
	}
}

func (s *Server) shouldUseHostedBudget(result *GrantexVerificationResult) bool {
	if s.config.Grantex == nil || !s.config.Grantex.EnforceGrant || s.hosted == nil || result == nil || !result.Valid || result.Grant == nil || result.Grant.GrantID == "" {
		return false
	}
	return s.config.Grantex.DebitBudgetBeforeChallenge == nil || *s.config.Grantex.DebitBudgetBeforeChallenge
}

func maxTransactionPaise(scopes []string) (int64, bool) {
	var cap int64
	found := false
	for _, scope := range scopes {
		if !strings.HasPrefix(scope, MaxTransactionScopePrefix) {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimPrefix(scope, MaxTransactionScopePrefix), 10, 64)
		if err != nil || value < 0 {
			continue
		}
		if !found || value < cap {
			cap, found = value, true
		}
	}
	return cap, found
}

func noStoreProblemHeaders() http.Header {
	return http.Header{"Content-Type": {"application/problem+json"}, "Cache-Control": {"no-store"}}
}

func stringifyMetadata(values map[string]interface{}) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		if text, ok := value.(string); ok {
			result[key] = text
			continue
		}
		raw, _ := json.Marshal(value)
		result[key] = string(raw)
	}
	return result
}

// Middleware protects a handler using fixed charge options.
func (s *Server) Middleware(options ChargeOptions, next http.Handler) http.Handler {
	return s.MiddlewareFunc(func(*http.Request) (ChargeOptions, error) { return options, nil }, next)
}

// MiddlewareFunc protects a handler using request-specific charge options.
func (s *Server) MiddlewareFunc(resolve ChargeOptionsResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		options, err := resolve(r)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "CHARGE_OPTIONS_FAILED", "message": err.Error()}, http.Header{"Content-Type": {"application/json"}})
			return
		}
		decision := s.DecidePayment(r.Context(), r.Header.Get("P3P-Credential"), r.Header.Get("Authorization"), r.Header.Get(GrantexTokenHeader), options)
		if decision.Action == "proceed" {
			copyHeaders(w.Header(), decision.Headers)
			next.ServeHTTP(w, r)
			return
		}
		body := decision.ProblemDetails
		if decision.Action == "pending" && decision.PendingBody != nil {
			body = decision.PendingBody
		}
		writeJSON(w, decision.Status, body, decision.Headers)
	})
}

func writeJSON(w http.ResponseWriter, status int, body interface{}, headers http.Header) {
	copyHeaders(w.Header(), headers)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func copyHeaders(target, source http.Header) {
	for key, values := range source {
		target.Del(key)
		for _, value := range values {
			target.Add(key, value)
		}
	}
}
