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
)

func (s *Server) createPreAuthorizationRequest(ctx context.Context, options CreateMandateOptions) (map[string]interface{}, error) {
	if err := validateMandateOptions(options); err != nil {
		return nil, err
	}
	mobile, _ := normalizeMobile(options.MobileNumber)
	method := options.PaymentMethod
	if method == "" {
		method = s.config.AvailablePaymentMethods[0]
	}
	validity := options.ValidityInDays
	if validity == 0 {
		validity = 7
	}
	payload := map[string]interface{}{"payment_method": method, "customer": map[string]string{"mobile_number": mobile}, "amount": options.Amount, "validity_in_days": validity}
	if options.Description != "" {
		payload["description"] = options.Description
	}
	if options.PaymentMethodOptions != nil {
		payload["payment_method_options"] = options.PaymentMethodOptions
	}
	if options.MerchantMetadata != nil {
		metadata := map[string]string{}
		for key, value := range options.MerchantMetadata {
			if text, ok := value.(string); ok {
				metadata[key] = text
			} else {
				raw, _ := json.Marshal(value)
				metadata[key] = string(raw)
			}
		}
		payload["merchant_metadata"] = metadata
	}
	headers := http.Header{"Idempotency-Key": {firstNonEmpty(options.IdempotencyKey, newID())}}
	data, err := s.apiRequest(ctx, http.MethodPost, "/mpp/v1/pre-authorize", payload, headers)
	if err != nil {
		return nil, err
	}
	if (method == PaymentMethodCard || method == PaymentMethodCreditEMI) && firstString(data, "redirect_url", "redirectUrl", "challenge_url", "challengeUrl") == "" {
		if token := firstString(data, "token"); token != "" {
			data["redirect_url"] = s.config.Env + "/api/v3/checkout-bff/redirect/checkout?token=" + checkoutTokenEscape(token)
		}
	}
	return data, nil
}

func (s *Server) apiRequest(ctx context.Context, method, path string, payload interface{}, headers http.Header) (map[string]interface{}, error) {
	token, err := s.auth.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	factory := func() (*http.Request, error) {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(raw)
		}
		req, requestErr := http.NewRequest(method, s.config.Env+path, reader)
		if requestErr == nil {
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Merchant-ID", s.config.MerchantID)
			if payload != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			for key, values := range headers {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}
		return req, requestErr
	}
	resp, err := doWithRetry(ctx, s.http, factory, *s.config.MaxRetries, s.config.InitialRetryDelay)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, errorFromResponse(resp.StatusCode, body)
	}
	var envelope map[string]interface{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, err
		}
	}
	if data := asMap(envelope["data"]); len(data) > 0 {
		return data, nil
	}
	return envelope, nil
}

func (s *Server) GetMandateBalance(ctx context.Context, options MandateBalanceLookupOptions) (MandateBalanceResult, error) {
	if options.PaymentMethod == "" {
		return MandateBalanceResult{}, fmt.Errorf("MandateBalanceLookupOptions: paymentMethod is required")
	}
	if !isSupportedPaymentMethod(options.PaymentMethod) {
		return MandateBalanceResult{}, unsupportedPaymentMethodError("MandateBalanceLookupOptions: paymentMethod", options.PaymentMethod)
	}
	if options.PaymentMethod == PaymentMethodOTM {
		return MandateBalanceResult{}, fmt.Errorf("MandateBalanceLookupOptions: OTM is not supported for mandate balance lookup")
	}
	query := url.Values{}
	if options.AuthorizationID != "" {
		query.Set("authorization_id", options.AuthorizationID)
		if options.PhoneNumber != "" {
			mobile, mobileErr := normalizeMobile(options.PhoneNumber)
			if mobileErr != nil {
				return MandateBalanceResult{}, mobileErr
			}
			if len(mobile) != 10 {
				return MandateBalanceResult{}, fmt.Errorf("MandateBalanceLookupOptions: phoneNumber must be 10 digits")
			}
			query.Set("phone_number", mobile)
		}
	} else {
		mobile, mobileErr := normalizeMobile(options.PhoneNumber)
		if mobileErr != nil {
			return MandateBalanceResult{}, mobileErr
		}
		if mobile == "" {
			return MandateBalanceResult{}, fmt.Errorf("MandateBalanceLookupOptions: phoneNumber is required when authorizationId is absent")
		}
		if len(mobile) != 10 {
			return MandateBalanceResult{}, fmt.Errorf("MandateBalanceLookupOptions: phoneNumber must be 10 digits")
		}
		query.Set("phone_number", mobile)
		query.Set("type", string(options.PaymentMethod))
	}
	data, err := s.apiRequest(ctx, http.MethodGet, "/mpp/v1/balance?"+query.Encode(), nil, nil)
	if err != nil {
		return MandateBalanceResult{}, err
	}
	return parseMandateBalance(data), nil
}

func (s *Server) RevokeMandate(ctx context.Context, options CreateMandateRevokeOptions) (MandateRevokeResult, error) {
	if !isSupportedPaymentMethod(options.PaymentMethod) {
		return MandateRevokeResult{}, unsupportedPaymentMethodError("CreateMandateRevokeOptions: paymentMethod", options.PaymentMethod)
	}
	if options.PaymentMethodReferenceID == "" && (options.Customer == nil || options.Customer.MerchantCustomerReference == "" && options.Customer.MobileNumber == "") {
		return MandateRevokeResult{}, fmt.Errorf("CreateMandateRevokeOptions: paymentMethodReferenceId or customer lookup is required")
	}
	payload := map[string]interface{}{"payment_method": options.PaymentMethod}
	if options.PaymentMethodReferenceID != "" {
		payload["payment_method_reference_id"] = options.PaymentMethodReferenceID
	}
	if options.Customer != nil {
		customer := map[string]string{}
		if options.Customer.MerchantCustomerReference != "" {
			customer["merchant_customer_reference"] = options.Customer.MerchantCustomerReference
		}
		if options.Customer.MobileNumber != "" {
			mobile, mobileErr := normalizeMobile(options.Customer.MobileNumber)
			if mobileErr != nil {
				return MandateRevokeResult{}, mobileErr
			}
			if len(mobile) != 10 {
				return MandateRevokeResult{}, fmt.Errorf("CreateMandateRevokeOptions: customer.mobileNumber must be 10 digits")
			}
			customer["mobile_number"] = mobile
		}
		if len(customer) > 0 {
			payload["customer"] = customer
		}
	}
	data, err := s.apiRequest(ctx, http.MethodPost, "/mpp/v1/revoke", payload, nil)
	if err != nil {
		return MandateRevokeResult{}, err
	}
	return MandateRevokeResult{PaymentMethod: PaymentMethod(firstString(data, "payment_method")), PaymentMethodReferenceID: firstString(data, "payment_method_reference_id"), RevokeReferenceID: firstString(data, "revoke_reference_id"), Status: firstString(data, "status"), Raw: data}, nil
}

func parseMandate(data map[string]interface{}) Mandate {
	metadata := asMap(data["metadata"])
	sbmd := asMap(metadata["sbmd_data"])
	customer := asMap(data["customer"])
	amount := asMap(firstNonNil(data["payment_amount"], data["paymentAmount"], data["amount"]))
	status := firstString(data, "payment_status", "order_status", "status")
	result := Mandate{MandateID: firstNonEmpty(firstString(data, "payment_method_reference_id", "authorization_id", "authorizationId", "mandate_id", "mandateId", "order_id", "orderId"), firstString(metadata, "external_subscription_id")), Object: firstNonEmpty(firstString(data, "object"), "mandate"), OrderID: firstNonEmpty(firstString(data, "order_id"), firstString(sbmd, "order_id")), OrderStatus: firstNonEmpty(firstString(data, "order_status"), status), PaymentStatus: firstNonEmpty(firstString(data, "payment_status"), status), CustomerReference: firstNonEmpty(firstString(customer, "merchant_customer_reference"), firstString(data, "merchant_customer_reference", "customer_reference", "customer_id")), CustomerID: firstNonEmpty(firstString(customer, "customer_id"), firstString(data, "customer_id", "customer_reference")), AgentID: firstString(data, "agent_id"), Amount: Amount{Value: asInt64(amount["value"]), Currency: firstNonEmpty(firstString(amount, "currency"), "INR")}, AmountBlocked: asInt64(firstNonNil(data["amount_blocked"], sbmd["amount_blocked"])), AmountDebited: asInt64(firstNonNil(data["amount_debited"], sbmd["amount_debited"])), AmountHeld: asInt64(firstNonNil(data["amount_held"], sbmd["amount_held"])), AmountAvailable: asInt64(firstNonNil(data["amount_available"], sbmd["amount_available"])), MobileNumber: firstNonEmpty(firstString(customer, "mobile_number"), firstString(data, "mobile_number")), Description: firstNonEmpty(firstString(data, "description"), firstString(metadata, "description")), Metadata: metadata, ExpiresAt: firstNonEmpty(firstString(data, "expiry_at", "expires_at"), firstString(sbmd, "expires_at")), CreatedAt: firstNonEmpty(firstString(data, "created_at"), firstString(sbmd, "created_at")), Raw: data}
	challenge := asMap(data["challenge"])
	challengeURL := firstString(data, "challenge_url", "challengeUrl", "redirect_url", "redirectUrl")
	if len(challenge) > 0 || challengeURL != "" {
		result.Challenge = &MandateChallenge{Type: firstNonEmpty(firstString(challenge, "type"), firstString(sbmd, "challenge_type")), QRURL: firstNonEmpty(firstString(challenge, "qr_url"), challengeURL), DeepLink: firstNonEmpty(firstString(challenge, "deep_link"), challengeURL), ExpiresAt: firstNonEmpty(firstString(challenge, "expires_at"), result.ExpiresAt)}
	}
	return result
}
func parsePreAuthorization(data map[string]interface{}) PreAuthorization {
	customer := asMap(data["customer"])
	amount := asMap(firstNonNil(data["amount"], data["payment_amount"], data["paymentAmount"]))
	redirect := firstString(data, "redirect_url", "redirectUrl")
	challenge := firstString(data, "challenge_url", "challengeUrl")
	return PreAuthorization{PaymentMethod: PaymentMethod(firstString(data, "payment_method", "type")), PaymentMethodReferenceID: firstString(data, "payment_method_reference_id", "authorization_id", "mandate_id", "order_id", "orderId"), Customer: PreAuthorizationCustomer{CustomerID: firstString(customer, "customer_id"), MerchantCustomerReference: firstString(customer, "merchant_customer_reference"), MobileNumber: firstNonEmpty(firstString(customer, "mobile_number"), firstString(data, "mobile_number"))}, Status: firstString(data, "status", "payment_status", "order_status"), Amount: Amount{Value: asInt64(amount["value"]), Currency: firstNonEmpty(firstString(amount, "currency"), "INR")}, ChallengeURL: firstNonEmpty(challenge, redirect), RedirectURL: firstNonEmpty(redirect, challenge), ValidityInDays: asInt(data["validity_in_days"]), ExpiryAt: firstString(data, "expiry_at", "expires_at"), Raw: data}
}
func parseMandateBalance(data map[string]interface{}) MandateBalanceResult {
	customer := asMap(data["customer"])
	result := MandateBalanceResult{PaymentMethod: PaymentMethod(firstString(data, "payment_method")), PaymentMethodReferenceID: firstString(data, "payment_method_reference_id"), MerchantID: firstString(data, "merchant_id"), Customer: MandateBalanceCustomer{MobileNumber: firstString(customer, "mobile_number"), MerchantCustomerReference: firstString(customer, "merchant_customer_reference"), BankAccountNumber: firstString(customer, "bank_account_number")}, Status: firstString(data, "status"), Description: firstString(data, "description"), ValidityInDays: asInt(data["validity_in_days"]), ExpiryAt: firstString(data, "expiry_at"), ChallengeURL: firstString(data, "challenge_url"), ExternalReferenceID: firstString(data, "external_reference_id"), CreatedAt: firstString(data, "created_at"), Raw: data}
	if amount := asMap(data["amount"]); len(amount) > 0 {
		result.Amount = &Amount{Value: asInt64(amount["value"]), Currency: firstNonEmpty(firstString(amount, "currency"), "INR")}
	}
	if balance := asMap(data["balance_details"]); len(balance) > 0 {
		debited, remaining := asMap(balance["amount_debited"]), asMap(balance["amount_remaining"])
		result.BalanceDetails = &MandateBalanceDetails{AmountDebited: Amount{Value: asInt64(debited["value"]), Currency: firstNonEmpty(firstString(debited, "currency"), "INR")}, AmountRemaining: Amount{Value: asInt64(remaining["value"]), Currency: firstNonEmpty(firstString(remaining, "currency"), "INR")}}
	}
	return result
}
func firstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
func pathEscape(value string) string { return url.PathEscape(value) }
func checkoutTokenEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "%25", "%")
}
