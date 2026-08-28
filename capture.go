package p3pserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var pendingDebitStatuses = map[string]bool{"PENDING": true, "CREATED": true, "OMS_PAYMENT_SUBMITTED": true, "PROCESSING": true}

func IsPendingDebitStatus(status string) bool {
	return pendingDebitStatuses[strings.ToUpper(strings.TrimSpace(status))]
}

func (s *Server) Capture(ctx context.Context, options CaptureOptions) (CaptureResult, error) {
	if !isSupportedPaymentMethod(options.PaymentMethod) {
		return CaptureResult{}, &CaptureError{Message: unsupportedPaymentMethodError("CaptureOptions: paymentMethod", options.PaymentMethod).Error()}
	}
	if options.Amount.Value <= 0 {
		return CaptureResult{}, &CaptureError{Message: "CaptureOptions: amount.value must be a positive integer (paise)"}
	}
	mobile, err := normalizeMobile(options.MobileNumber)
	if err != nil || mobile == "" {
		return CaptureResult{}, &CaptureError{Message: "CaptureOptions: mobileNumber is required for P3P V2 debit"}
	}
	if strings.TrimSpace(options.ChallengeID) == "" {
		return CaptureResult{}, &CaptureError{Message: "CaptureOptions: challengeId is required for P3P V2 debit"}
	}
	reference := strings.TrimSpace(options.PaymentMethodReferenceID)
	if reference == "" && options.Metadata != nil {
		reference = firstNonEmpty(options.Metadata["payment_method_reference_id"], options.Metadata["authorization_id"], options.Metadata["mandate_id"])
	}
	if options.PaymentMethod == PaymentMethodCreditEMI && reference == "" {
		return CaptureResult{}, &CaptureError{Message: "CaptureOptions: paymentMethodReferenceID is required for CREDIT_EMI"}
	}
	idempotency := firstNonEmpty(options.IdempotencyKey, options.MerchantOrderReference, newID())
	token, err := s.auth.accessToken(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	payload := map[string]interface{}{"payment_method": options.PaymentMethod, "customer": map[string]string{"mobile_number": mobile}, "payment_amount": options.Amount, "payment_token": options.Token, "challenge_id": options.ChallengeID}
	if reference != "" {
		payload["payment_method_reference_id"] = reference
	}
	raw, _ := json.Marshal(payload)
	factory := func() (*http.Request, error) {
		req, requestErr := http.NewRequest(http.MethodPost, s.config.Env+"/mpp/v1/debit", bytes.NewReader(raw))
		if requestErr == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", idempotency)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Merchant-ID", s.config.MerchantID)
		}
		return req, requestErr
	}
	resp, err := doWithRetry(ctx, s.http, factory, *s.config.MaxRetries, s.config.InitialRetryDelay)
	if err != nil {
		return CaptureResult{}, err
	}
	result, parseErr := parseCaptureResponse(resp, s.config.PaymentGateway, idempotency)
	if parseErr != nil {
		return CaptureResult{}, parseErr
	}
	if resp.StatusCode == http.StatusAccepted {
		delay := retryDelay(resp.Header.Get("Retry-After"), s.config.InitialRetryDelay)
		result.Pending = true
		result.Message = "Payment accepted and still processing"
		result.RetryAfter = delay
		for attempt := 0; attempt < *s.config.MaxRetries; attempt++ {
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return CaptureResult{}, ctx.Err()
				case <-timer.C:
				}
			}
			polled, pollErr := s.getDebitStatus(ctx, idempotency)
			if pollErr != nil {
				return result, nil
			}
			if !IsPendingDebitStatus(polled.Status) {
				return polled, nil
			}
		}
		return result, nil
	}
	if resp.StatusCode >= 400 {
		return CaptureResult{}, captureErrorFromResult(resp.StatusCode, result.Raw)
	}
	return result, nil
}

func (s *Server) getDebitStatus(ctx context.Context, idempotency string) (CaptureResult, error) {
	if strings.TrimSpace(idempotency) == "" {
		return CaptureResult{}, fmt.Errorf("idempotency_key is required")
	}
	token, err := s.auth.accessToken(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	target := s.config.Env + "/mpp/v1/debit/" + url.PathEscape(idempotency)
	factory := func() (*http.Request, error) {
		req, requestErr := http.NewRequest(http.MethodGet, target, nil)
		if requestErr == nil {
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Merchant-ID", s.config.MerchantID)
		}
		return req, requestErr
	}
	resp, err := doWithRetry(ctx, s.http, factory, *s.config.MaxRetries, s.config.InitialRetryDelay)
	if err != nil {
		return CaptureResult{}, err
	}
	result, parseErr := parseCaptureResponse(resp, s.config.PaymentGateway, idempotency)
	if parseErr != nil {
		return CaptureResult{}, parseErr
	}
	if resp.StatusCode >= 400 {
		return CaptureResult{}, captureErrorFromResult(resp.StatusCode, result.Raw)
	}
	return result, nil
}

func parseCaptureResponse(resp *http.Response, gateway PaymentGateway, idempotency string) (CaptureResult, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return CaptureResult{}, err
	}
	var envelope map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return CaptureResult{}, err
		}
	}
	data := asMap(envelope["data"])
	if len(data) == 0 {
		data = envelope
	}
	result := CaptureResult{PaymentMethodReferenceID: firstString(data, "payment_method_reference_id"), PaymentID: firstString(data, "payment_id"), MerchantPaymentDebitReference: firstString(data, "merchant_payment_debit_reference"), MerchantOrderReference: firstString(data, "merchant_order_reference"), CaptureID: firstString(data, "capture_id"), OrderID: firstString(data, "order_id"), Status: firstString(data, "status"), SettledAt: firstString(data, "settled_at"), PaymentGateway: gateway, PaymentMethod: PaymentMethod(firstString(data, "payment_method")), IdempotencyKey: idempotency, Raw: data}
	if amount := asMap(data["amount"]); len(amount) > 0 {
		result.Amount = &Amount{Value: asInt64(amount["value"]), Currency: firstNonEmpty(firstString(amount, "currency"), "INR")}
	}
	return result, nil
}
func captureErrorFromResult(status int, data map[string]interface{}) error {
	raw, _ := json.Marshal(data)
	cause := errorFromResponse(status, raw)
	return &CaptureError{Message: "Capture failed: " + cause.Message, Cause: cause}
}
func retryDelay(header string, fallback time.Duration) time.Duration {
	if seconds, err := strconv.ParseFloat(header, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	return fallback
}
