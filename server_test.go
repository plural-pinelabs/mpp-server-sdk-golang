package p3pserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func intPointer(value int) *int { return &value }

func testConfig(baseURL string, client HTTPDoer) Config {
	return Config{ClientID: "client", ClientSecret: "secret", MerchantID: "merchant-test", PaymentGateway: PaymentGatewayPineLabsOnline, AvailablePaymentMethods: []PaymentMethod{PaymentMethodReservePay, PaymentMethodOTM, PaymentMethodCard, PaymentMethodCreditEMI}, Env: baseURL, Realm: "https://merchant.example", MaxRetries: intPointer(0), InitialRetryDelay: time.Nanosecond, HTTPClient: client}
}

func TestNewValidatesRequiredConfigurationAndTransport(t *testing.T) {
	config := testConfig("http://localhost:9999", nil)
	config.MerchantID = ""
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "merchantId") {
		t.Fatalf("expected merchantId validation, got %v", err)
	}
	config = testConfig("http://example.com", nil)
	if _, err := New(config); err == nil {
		t.Fatal("expected remote plain HTTP URL to be rejected")
	}
	config = testConfig("http://localhost:9999", nil)
	config.AvailablePaymentMethods = []PaymentMethod{PaymentMethodCrypto}
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported CRYPTO validation, got %v", err)
	}
}

func TestChallengeAndCredentialRoundTripRejectsTamperingAndExpiry(t *testing.T) {
	server, err := New(testConfig("http://localhost:9999", nil))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := server.GenerateChallenge(ChargeOptions{Amount: Amount{Value: 1299, Currency: "INR"}, Resource: "/premium"})
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{Challenge: challenge.Challenge, Source: "9876543210", Payload: CredentialPayload{Type: "payment-token", Token: "ppt_1", PaymentMethod: PaymentMethodReservePay, MobileNumber: "9876543210"}}
	header := credentialHeader(t, credential)
	if result := server.VerifyCredential(header); !result.Valid {
		t.Fatalf("valid credential rejected: %s", result.Error)
	}

	tampered := credential
	tampered.Challenge.Request.Amount = "1.00"
	if result := server.VerifyCredential(credentialHeader(t, tampered)); result.Valid || !strings.Contains(result.Error, "HMAC") {
		t.Fatalf("tampered credential accepted: %+v", result)
	}

	expired := credential
	expired.Challenge.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	encodedRequest, _ := EncodeJSON(expired.Challenge.Request)
	expired.Challenge.ID = computeChallengeID(deriveChallengeHMACKey("secret"), expired.Challenge.Realm, expired.Challenge.Intent, encodedRequest, expired.Challenge.Expires)
	if result := server.VerifyCredential(credentialHeader(t, expired)); result.Valid || !strings.Contains(result.Error, "expired") {
		t.Fatalf("expired credential accepted: %+v", result)
	}

	wrongMethod := credential
	wrongMethod.Payload.PaymentMethod = PaymentMethod("BANK_TRANSFER")
	if result := server.VerifyCredential(credentialHeader(t, wrongMethod)); result.Valid || !strings.Contains(result.Error, "not accepted") {
		t.Fatalf("unadvertised method accepted: %+v", result)
	}
}

func TestCreateCreditEMIPreAuthorizationPreservesPaymentMethodOnWire(t *testing.T) {
	var authCalls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			authCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/mpp/v1/pre-authorize":
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("Merchant-ID") != "merchant-test" || r.Header.Get("Idempotency-Key") != "idem-1" {
				t.Errorf("wrong headers: %v", r.Header)
			}
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["payment_method"] != "CREDIT_EMI" {
				t.Errorf("CREDIT_EMI must be preserved on the wire: %#v", body)
			}
			metadata := asMap(body["merchant_metadata"])
			if metadata["offer_data"] != `{"offer":true}` || metadata["plain"] != "value" {
				t.Errorf("metadata was not serialized correctly: %#v", metadata)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"payment_method": "CREDIT_EMI", "payment_method_reference_id": "auth_1", "token": "checkout token", "status": "PENDING", "customer": map[string]interface{}{"mobile_number": "9876543210"}, "amount": map[string]interface{}{"value": 50000, "currency": "INR"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	server, err := New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.CreatePreAuthorization(context.Background(), CreatePreAuthorizationOptions{Amount: Amount{Value: 50000, Currency: "INR"}, MobileNumber: "98765 43210", PaymentMethod: PaymentMethodCreditEMI, IdempotencyKey: "idem-1", MerchantMetadata: map[string]interface{}{"offer_data": map[string]interface{}{"offer": true}, "plain": "value"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.PaymentMethod != PaymentMethodCreditEMI || result.PaymentMethodReferenceID != "auth_1" || !strings.Contains(result.RedirectURL, "checkout+token") {
		t.Fatalf("wrong pre-authorization: %+v", result)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("expected one auth request, got %d", authCalls.Load())
	}
}

func TestCreateCardPreAuthorizationNormalizesLiveChallengeOnlyResponse(t *testing.T) {
	const challengeURL = "https://pluraluat.v2.pinepg.in/api/v3/checkout-bff/redirect/checkout?flow=CARD&token=V3_live_shape"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/mpp/v1/pre-authorize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"payment_method":              "CARD",
				"payment_method_reference_id": "auth_live_shape",
				"challenge_url":               challengeURL,
				"token":                       "must-not-replace-live-challenge",
				"status":                      "PENDING",
				"customer":                    map[string]interface{}{"mobile_number": "9390012811"},
				"amount":                      map[string]interface{}{"value": 50000, "currency": "INR"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	server, err := New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.CreatePreAuthorization(context.Background(), CreatePreAuthorizationOptions{
		Amount:         Amount{Value: 50000, Currency: "INR"},
		MobileNumber:   "9390012811",
		PaymentMethod:  PaymentMethodCard,
		IdempotencyKey: "idem-live-shape",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PaymentMethodReferenceID != "auth_live_shape" || result.ChallengeURL != challengeURL || result.RedirectURL != challengeURL {
		t.Fatalf("challenge-only response was not normalized: %+v", result)
	}
	if _, exists := result.Raw["redirect_url"]; exists {
		t.Fatalf("raw live response must preserve the absence of redirect_url: %#v", result.Raw)
	}
}

func TestCreditEMICaptureSendsPreAuthorizationReference(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/mpp/v1/debit":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["payment_method"] != "CREDIT_EMI" || body["payment_method_reference_id"] != "auth_credit_emi" {
				t.Errorf("wrong CREDIT_EMI debit body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "PROCESSED", "payment_method": "CREDIT_EMI", "payment_method_reference_id": "auth_credit_emi", "payment_amount": map[string]interface{}{"value": 14897000, "currency": "INR"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	server, err := New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.Capture(context.Background(), CaptureOptions{Token: "ppt_credit_emi", Amount: Amount{Value: 14897000, Currency: "INR"}, PaymentMethod: PaymentMethodCreditEMI, PaymentMethodReferenceID: "auth_credit_emi", MobileNumber: "9390012811", ChallengeID: "ch_credit_emi", IdempotencyKey: "debit-credit-emi"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PaymentMethodReferenceID != "auth_credit_emi" || result.PaymentMethod != PaymentMethodCreditEMI || result.Amount == nil || result.Amount.Value != 14897000 {
		t.Fatalf("wrong capture result: %+v", result)
	}
}

func TestCreditEMICaptureRejectsMissingPreAuthorizationReferenceBeforeNetwork(t *testing.T) {
	server, err := New(testConfig("http://localhost:9999", nil))
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Capture(context.Background(), CaptureOptions{Token: "ppt_credit_emi", Amount: Amount{Value: 1000, Currency: "INR"}, PaymentMethod: PaymentMethodCreditEMI, MobileNumber: "9390012811", ChallengeID: "ch_credit_emi"})
	if err == nil || !strings.Contains(err.Error(), "paymentMethodReferenceID is required") {
		t.Fatalf("expected missing reference error, got %v", err)
	}
}

func TestCaptureAcceptedPollsWithGETAndNeverReposts(t *testing.T) {
	var postCalls, getCalls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case r.URL.Path == "/mpp/v1/debit" && r.Method == http.MethodPost:
			postCalls.Add(1)
			if r.Header.Get("Merchant-ID") != "merchant-test" || r.Header.Get("Idempotency-Key") != "idem-202" {
				t.Errorf("wrong debit headers: %v", r.Header)
			}
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "PENDING"}})
		case r.URL.Path == "/mpp/v1/debit/idem-202" && r.Method == http.MethodGet:
			call := getCalls.Add(1)
			status := "PROCESSING"
			if call == 2 {
				status = "SUCCESS"
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": status, "capture_id": "cap_1", "payment_method": "RESERVE_PAY", "amount": map[string]interface{}{"value": 2500, "currency": "INR"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	config := testConfig(backend.URL, backend.Client())
	config.MaxRetries = intPointer(2)
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.Capture(context.Background(), CaptureOptions{Token: "ppt", Amount: Amount{Value: 2500, Currency: "INR"}, PaymentMethod: PaymentMethodReservePay, IdempotencyKey: "idem-202", MobileNumber: "9876543210", ChallengeID: "ch_1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "SUCCESS" || result.CaptureID != "cap_1" || postCalls.Load() != 1 || getCalls.Load() != 2 {
		t.Fatalf("result=%+v post=%d get=%d", result, postCalls.Load(), getCalls.Load())
	}
}

func TestReceiptHeaderRoundTripUsesCaptureReferenceFirst(t *testing.T) {
	capture := CaptureResult{CaptureID: "cap_1", MerchantPaymentDebitReference: "debit_1", MerchantOrderReference: "order-ref", OrderID: "order_1", Status: "SUCCESS", Amount: &Amount{Value: 1299, Currency: "INR"}, PaymentGateway: PaymentGatewayPineLabsOnline, PaymentMethod: PaymentMethodOTM}
	header, err := BuildReceiptHeader(capture, "ch_1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "Payment ") {
		t.Fatalf("wrong header: %q", header)
	}
	var receipt ReceiptData
	if err := DecodeJSON(strings.TrimPrefix(header, "Payment "), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Reference != "cap_1" || receipt.Settlement == nil || receipt.Settlement.Amount != "12.99" || receipt.PaymentMethod != PaymentMethodOTM {
		t.Fatalf("wrong receipt: %+v", receipt)
	}
}

func TestMandateLookupAndRevokeValidateBeforeNetwork(t *testing.T) {
	server, err := New(testConfig("http://localhost:9999", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.GetMandate(context.Background(), " "); err == nil || !strings.Contains(err.Error(), "mandate_id") {
		t.Fatalf("expected mandate id validation, got %v", err)
	}
	if _, err := server.GetMandateBalance(context.Background(), MandateBalanceLookupOptions{PhoneNumber: "123", PaymentMethod: PaymentMethodCard}); err == nil || !strings.Contains(err.Error(), "10 digits") {
		t.Fatalf("expected balance phone validation, got %v", err)
	}
	if _, err := server.RevokeMandate(context.Background(), CreateMandateRevokeOptions{PaymentMethod: PaymentMethodCard, Customer: &RevokeMandateCustomerLookup{}}); err == nil || !strings.Contains(err.Error(), "customer lookup") {
		t.Fatalf("expected revoke lookup validation, got %v", err)
	}
}

func TestErrorParserSupportsTopLevelAndStringErrors(t *testing.T) {
	topLevel := errorFromResponse(http.StatusBadRequest, []byte(`{"code":"INVALID_REQUEST","message":"customer reference is required"}`))
	if topLevel.Code != "INVALID_REQUEST" || topLevel.Message != "customer reference is required" {
		t.Fatalf("wrong top-level error: %+v", topLevel)
	}
	stringError := errorFromResponse(http.StatusBadRequest, []byte(`{"error":"missing request header"}`))
	if stringError.Message != "missing request header" {
		t.Fatalf("wrong string error: %+v", stringError)
	}
}

func TestHTTPMiddlewareChallengesThenCapturesAndProceeds(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/mpp/v1/debit":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "SUCCESS", "capture_id": "cap_mw", "payment_method": "RESERVE_PAY", "amount": map[string]interface{}{"value": 9900, "currency": "INR"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	server, err := New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	options := ChargeOptions{Amount: Amount{Value: 9900, Currency: "INR"}, Resource: "/premium", MerchantOrderReference: "order-1"}
	called := false
	handler := server.Middleware(options, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/premium", nil))
	if first.Code != http.StatusPaymentRequired || !strings.HasPrefix(first.Header().Get("WWW-Authenticate"), "Payment ") || called {
		t.Fatalf("wrong challenge response: code=%d headers=%v called=%t", first.Code, first.Header(), called)
	}
	var challenge Challenge
	if err := DecodeJSON(strings.TrimPrefix(first.Header().Get("WWW-Authenticate"), "Payment "), &challenge); err != nil {
		t.Fatal(err)
	}
	credential := Credential{Challenge: challenge, Source: "9876543210", Payload: CredentialPayload{Type: "payment-token", Token: "ppt", PaymentMethod: PaymentMethodReservePay, MobileNumber: "9876543210"}}
	secondRequest := httptest.NewRequest(http.MethodGet, "/premium", nil)
	secondRequest.Header.Set("P3P-Credential", credentialHeader(t, credential))
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusNoContent || !called || !strings.HasPrefix(second.Header().Get("Payment-Receipt"), "Payment ") {
		t.Fatalf("wrong paid response: code=%d headers=%v called=%t body=%s", second.Code, second.Header(), called, second.Body.String())
	}
}

type fixedVerifier struct{ result GrantexVerificationResult }

func (v fixedVerifier) Verify(context.Context, string) GrantexVerificationResult { return v.result }

func TestGrantexEnforcementAndHostedAPIs(t *testing.T) {
	if !HasGrantScope([]string{"mpp:payment:*"}, "mpp:payment:create") {
		t.Fatal("wildcard grant scope must cover its child")
	}
	var hostedCalls atomic.Int32
	var authorizePayload map[string]interface{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gx-key" {
			t.Errorf("missing hosted authentication: %v", r.Header)
		}
		hostedCalls.Add(1)
		switch r.URL.Path {
		case "/v1/authorize":
			_ = json.NewDecoder(r.Body).Decode(&authorizePayload)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "consentUrl": "https://consent.example", "agentId": "agent_1", "principalId": "user_1", "scopes": []string{"mpp:payment:create"}})
		case "/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"grantToken": "grant.jwt", "grantId": "grant_1", "refreshToken": "refresh", "scopes": []string{"mpp:payment:create"}})
		case "/v1/budget/allocate":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "budget_1", "grantId": "grant_1", "initialBudget": "100.00", "remainingBudget": "100.00", "currency": "INR"})
		case "/v1/budget/debit":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"remaining": "87.50", "transactionId": "txn_1"})
		case "/v1/budget/balance/grant_1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "budget_1", "grantId": "grant_1", "initialBudget": "100.00", "remainingBudget": "87.50", "currency": "INR"})
		case "/v1/budget/transactions/grant_1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"total": 1, "transactions": []interface{}{map[string]interface{}{"id": "txn_1", "amount": "12.50", "balanceAfter": "87.50"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	hosted, err := NewHostedGrantexClient(HostedGrantexConfig{APIKey: "gx-key", BaseURL: backend.URL, HTTPClient: backend.Client(), MaxRetries: intPointer(0)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	auth, err := hosted.CreateAuthorization(ctx, GrantexAuthorizationOptions{UserID: "user_1", AgentID: "agent_1", Scopes: []string{"mpp:payment:create"}, RedirectURI: "https://merchant.example/callback", State: "0123456789abcdef0123456789abcdef"})
	if err != nil || auth.AuthRequestID != "req_1" {
		t.Fatalf("authorization=%+v err=%v", auth, err)
	}
	if authorizePayload["state"] != "0123456789abcdef0123456789abcdef" || authorizePayload["redirectUri"] != "https://merchant.example/callback" {
		t.Fatalf("authorization payload=%#v", authorizePayload)
	}
	token, err := hosted.ExchangeCode(ctx, GrantexExchangeCodeOptions{Code: "code", AgentID: "agent_1"})
	if err != nil || token.GrantID != "grant_1" {
		t.Fatalf("token=%+v err=%v", token, err)
	}
	budget, err := hosted.AllocateBudget(ctx, GrantexBudgetAllocationOptions{GrantID: "grant_1", InitialBudget: 100, Currency: "INR"})
	if err != nil || budget.RemainingBudget != 100 {
		t.Fatalf("budget=%+v err=%v", budget, err)
	}
	debit, err := hosted.DebitBudget(ctx, GrantexBudgetDebitOptions{GrantID: "grant_1", Amount: 12.5})
	if err != nil || debit.Remaining != 87.5 {
		t.Fatalf("debit=%+v err=%v", debit, err)
	}
	balance, err := hosted.GetBudgetBalance(ctx, "grant_1")
	if err != nil || balance.RemainingBudget != 87.5 {
		t.Fatalf("balance=%+v err=%v", balance, err)
	}
	transactions, err := hosted.ListBudgetTransactions(ctx, "grant_1", &GrantexBudgetTransactionsOptions{Limit: 10})
	if err != nil || transactions.Total != 1 || len(transactions.Transactions) != 1 {
		t.Fatalf("transactions=%+v err=%v", transactions, err)
	}
	if hostedCalls.Load() != 6 {
		t.Fatalf("expected all hosted surfaces to be called, got %d", hostedCalls.Load())
	}

	config := testConfig("http://localhost:9999", nil)
	config.Grantex = &ServerGrantexConfig{EnforceGrant: true, Hosted: &HostedGrantexConfig{APIKey: "dummy", BaseURL: "http://localhost:9998"}, Verifier: fixedVerifier{result: GrantexVerificationResult{Error: "bad grant"}}}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	missing := server.DecidePayment(ctx, "", "", "", ChargeOptions{Amount: Amount{Value: 100, Currency: "INR"}, Resource: "/paid"})
	if missing.Action != "grant_required" || missing.Status != http.StatusForbidden {
		t.Fatalf("missing grant was not rejected: %+v", missing)
	}
	invalid := server.DecidePayment(ctx, "", "", "bad", ChargeOptions{Amount: Amount{Value: 100, Currency: "INR"}, Resource: "/paid"})
	if invalid.Action != "grant_invalid" {
		t.Fatalf("invalid grant was not rejected: %+v", invalid)
	}
}

func credentialHeader(t *testing.T, credential Credential) string {
	t.Helper()
	encoded, err := EncodeJSON(credential)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("Payment %s", encoded)
}
