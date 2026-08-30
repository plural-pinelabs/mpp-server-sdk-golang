package p3pserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateRefundSendsRequiredRequestAndParsesResponse(t *testing.T) {
	const parentOrderID = "v1-241010055924-aa-AHbN0s"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/api/pay/v1/refunds/" + parentOrderID:
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("Merchant-ID") != "merchant-test" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("wrong standard headers: %v", r.Header)
			}
			if r.Header.Get("Request-ID") == "" {
				t.Error("Request-ID is missing")
			}
			if _, err := time.Parse(time.RFC3339Nano, r.Header.Get("Request-Timestamp")); err != nil {
				t.Errorf("invalid Request-Timestamp %q: %v", r.Header.Get("Request-Timestamp"), err)
			}
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["merchant_order_reference"] != "refund-reference-123" {
				t.Errorf("wrong merchant_order_reference: %#v", body)
			}
			amount := asMap(body["order_amount"])
			if asInt64(amount["value"]) != 1100 || amount["currency"] != "INR" {
				t.Errorf("wrong order_amount: %#v", amount)
			}
			metadata := asMap(body["merchant_metadata"])
			if metadata["key1"] != "DD" || metadata["key_2"] != "XOF" {
				t.Errorf("wrong merchant_metadata: %#v", metadata)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"order_id": "v1-241010071949-aa-vcqtJY", "parent_order_id": parentOrderID, "merchant_order_reference": "refund-reference-123", "type": "REFUND", "status": "PROCESSED", "merchant_id": "108272",
				"order_amount": map[string]interface{}{"value": 400, "currency": "INR"},
				"payments": []interface{}{map[string]interface{}{
					"id": "v1-241010071949-aa-vcqtJY-cc-b", "status": "PROCESSED", "payment_amount": map[string]interface{}{"value": 400, "currency": "INR"}, "payment_method": "CARD",
					"acquirer_data": map[string]interface{}{"approval_code": "", "acquirer_reference": "7285447904236780703954", "rrn": "", "is_aggregator": true},
					"created_at":    "2024-10-10T07:19:49.423Z", "updated_at": "2024-10-10T07:19:51.205Z",
				}},
				"created_at": "2024-10-10T07:19:49.424Z", "updated_at": "2024-10-10T07:19:51.205Z", "future_field": "retained",
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
	refund, err := server.CreateRefund(context.Background(), "  "+parentOrderID+"  ", CreateRefundOptions{
		MerchantOrderReference: " refund-reference-123 ",
		OrderAmount:            Amount{Value: 1100, Currency: " INR "},
		MerchantMetadata:       map[string]interface{}{"key1": "DD", "key_2": "XOF"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if refund.OrderID != "v1-241010071949-aa-vcqtJY" || refund.ParentOrderID != parentOrderID || refund.Type != "REFUND" || refund.Status != "PROCESSED" || refund.MerchantID != "108272" {
		t.Fatalf("wrong refund summary: %+v", refund)
	}
	if refund.OrderAmount != (Amount{Value: 400, Currency: "INR"}) || len(refund.Payments) != 1 {
		t.Fatalf("wrong refund amount/payments: %+v", refund)
	}
	payment := refund.Payments[0]
	if payment.PaymentMethod != PaymentMethodCard || payment.AcquirerData.AcquirerReference != "7285447904236780703954" || !payment.AcquirerData.IsAggregator {
		t.Fatalf("wrong refund payment: %+v", payment)
	}
	if refund.Raw["future_field"] != "retained" {
		t.Fatalf("raw response was not retained: %#v", refund.Raw)
	}
}

func TestCreateRefundValidatesInputAndReturnsAPIError(t *testing.T) {
	server, err := New(testConfig("http://localhost:9999", nil))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		orderID string
		options CreateRefundOptions
		want    string
	}{
		{name: "order ID", orderID: " ", options: CreateRefundOptions{}, want: "order_id is required"},
		{name: "merchant reference", orderID: "order-1", options: CreateRefundOptions{OrderAmount: Amount{Value: 100, Currency: "INR"}}, want: "merchantOrderReference is required"},
		{name: "amount", orderID: "order-1", options: CreateRefundOptions{MerchantOrderReference: "refund-1", OrderAmount: Amount{Currency: "INR"}}, want: "orderAmount.value must be a positive integer"},
		{name: "currency", orderID: "order-1", options: CreateRefundOptions{MerchantOrderReference: "refund-1", OrderAmount: Amount{Value: 100}}, want: "orderAmount.currency is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := server.CreateRefund(context.Background(), test.orderID, test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/api/pay/v1/refunds/not-processed":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": "INVALID_ORDER_STATUS", "message": "Order must be processed before refund"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	server, err = New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.CreateRefund(context.Background(), "not-processed", CreateRefundOptions{MerchantOrderReference: "refund-1", OrderAmount: Amount{Value: 100, Currency: "INR"}})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusBadRequest || apiErr.Code != "INVALID_ORDER_STATUS" {
		t.Fatalf("wrong API error: %#v", err)
	}
}
