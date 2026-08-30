package p3pserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGetOrderUsesConfiguredTransportAndParsesResponse(t *testing.T) {
	const orderID = "v1-5757575757-aa-hU1rUd"
	var authCalls, orderCalls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			authCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/api/pay/v1/orders/" + orderID:
			orderCalls.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("method = %s, want GET", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("Merchant-ID") != "merchant-test" || r.Header.Get("Accept") != "application/json" {
				t.Errorf("wrong headers: %v", r.Header)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"order_id": orderID, "merchant_order_reference": "2177120b-3be1-4330-a15f-53ce14d19841", "type": "CHARGE", "status": "CANCELLED", "merchant_id": "123456",
				"order_amount": map[string]interface{}{"value": 50000, "currency": "INR"}, "pre_auth": true,
				"purchase_details": map[string]interface{}{
					"customer": map[string]interface{}{
						"email_id": "kevin.bob@example.com", "first_name": "Kevin", "last_name": "Bob", "customer_id": "232323", "mobile_number": "9876543210",
						"billing_address":  map[string]interface{}{"address1": "H.No 15, Sector 17", "pincode": "61232112", "city": "CHANDIGARH", "state": "PUNJAB", "country": "INDIA"},
						"shipping_address": map[string]interface{}{"address1": "H.No 15, Sector 17", "pincode": "144001123", "city": "CHANDIGARH", "state": "PUNJAB", "country": "INDIA"},
					},
					"merchant_metadata": map[string]interface{}{"key1": "DD", "key2": "XOF"},
				},
				"payments": []interface{}{map[string]interface{}{
					"id": "v1-2711071924-aa-VxIzq1-cc-Z", "status": "CANCELLED", "payment_amount": map[string]interface{}{"value": 1100, "currency": "INR"}, "payment_method": "CARD",
					"payment_option": map[string]interface{}{"card_data": map[string]interface{}{"card_type": "CREDIT", "network_name": "VISA", "issuer_name": "NONE", "card_category": "CONSUMER", "country_code": "IND", "token_txn_type": "ALT_TOKEN"}},
					"acquirer_data":  map[string]interface{}{"approval_code": "000000", "acquirer_reference": "202456644249243", "rrn": "420123000239"},
					"created_at":     "2024-07-19T11:27:55.664Z", "updated_at": "2024-07-19T11:28:52.487Z",
				}},
				"created_at": "2024-07-19T11:27:55.664Z", "updated_at": "2024-07-19T11:28:52.487Z", "future_field": "retained-in-raw",
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
	order, err := server.GetOrder(context.Background(), "  "+orderID+"  ")
	if err != nil {
		t.Fatal(err)
	}
	if authCalls.Load() != 1 || orderCalls.Load() != 1 {
		t.Fatalf("auth calls = %d, order calls = %d", authCalls.Load(), orderCalls.Load())
	}
	if order.OrderID != orderID || order.MerchantOrderReference != "2177120b-3be1-4330-a15f-53ce14d19841" || order.Type != "CHARGE" || order.Status != "CANCELLED" || order.MerchantID != "123456" || !order.PreAuth {
		t.Fatalf("wrong order summary: %+v", order)
	}
	if order.OrderAmount != (Amount{Value: 50000, Currency: "INR"}) {
		t.Fatalf("wrong order amount: %+v", order.OrderAmount)
	}
	customer := order.PurchaseDetails.Customer
	if customer.EmailID != "kevin.bob@example.com" || customer.MobileNumber != "9876543210" || customer.BillingAddress.Pincode != "61232112" || customer.ShippingAddress.Pincode != "144001123" {
		t.Fatalf("wrong customer: %+v", customer)
	}
	if order.PurchaseDetails.MerchantMetadata["key2"] != "XOF" {
		t.Fatalf("wrong merchant metadata: %#v", order.PurchaseDetails.MerchantMetadata)
	}
	if len(order.Payments) != 1 {
		t.Fatalf("payments = %#v", order.Payments)
	}
	payment := order.Payments[0]
	if payment.ID != "v1-2711071924-aa-VxIzq1-cc-Z" || payment.PaymentMethod != PaymentMethodCard || payment.PaymentAmount.Value != 1100 || payment.PaymentOption.CardData == nil || payment.PaymentOption.CardData.NetworkName != "VISA" || payment.AcquirerData.RRN != "420123000239" {
		t.Fatalf("wrong payment: %+v", payment)
	}
	if order.Raw["future_field"] != "retained-in-raw" {
		t.Fatalf("raw response was not retained: %#v", order.Raw)
	}
}

func TestGetOrderValidatesIDAndReturnsAPIError(t *testing.T) {
	server, err := New(testConfig("http://localhost:9999", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.GetOrder(context.Background(), " \t "); err == nil || !strings.Contains(err.Error(), "order_id is required") {
		t.Fatalf("expected local order ID validation, got %v", err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v1/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"access_token": "access", "expires_in": 3600}})
		case "/api/pay/v1/orders/missing-order":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": "ORDER_NOT_FOUND", "message": "Order not found"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	server, err = New(testConfig(backend.URL, backend.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.GetOrder(context.Background(), "missing-order")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusNotFound || apiErr.Code != "ORDER_NOT_FOUND" || apiErr.Message != "Order not found" {
		t.Fatalf("wrong API error: %#v", err)
	}
}
