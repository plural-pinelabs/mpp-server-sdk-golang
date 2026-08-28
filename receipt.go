package p3pserver

import (
	"fmt"
	"time"
)

const PaymentReceiptPrefix = "Payment "

// BuildReceiptData creates the structured receipt returned after a successful
// payment capture.
func BuildReceiptData(capture CaptureResult, challengeID string, gateway PaymentGateway, method PaymentMethod) ReceiptData {
	timestamp := capture.SettledAt
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	reference := firstNonEmpty(capture.CaptureID, capture.MerchantPaymentDebitReference)
	merchantReference := firstNonEmpty(capture.MerchantOrderReference, capture.MerchantPaymentDebitReference)
	if gateway == "" {
		gateway = capture.PaymentGateway
	}
	if method == "" {
		method = capture.PaymentMethod
	}
	receipt := ReceiptData{Status: "success", Timestamp: timestamp, Reference: reference, ChallengeID: challengeID, PaymentGateway: gateway, PaymentMethod: method, OrderID: capture.OrderID, MerchantOrderReference: merchantReference}
	if capture.Amount != nil {
		receipt.Settlement = &Settlement{Amount: fmt.Sprintf("%.2f", float64(capture.Amount.Value)/100), Currency: capture.Amount.Currency}
	}
	return receipt
}

// BuildReceiptHeader encodes receipt data in the MPP `Payment <base64url>`
// header format.
func BuildReceiptHeader(capture CaptureResult, challengeID string, gateway PaymentGateway, method PaymentMethod) (string, error) {
	payload, err := EncodeJSON(BuildReceiptData(capture, challengeID, gateway, method))
	if err != nil {
		return "", err
	}
	return PaymentReceiptPrefix + payload, nil
}

func (s *Server) BuildReceiptData(capture CaptureResult, challengeID string, gateway PaymentGateway, method PaymentMethod) ReceiptData {
	if gateway == "" {
		gateway = s.config.PaymentGateway
	}
	return BuildReceiptData(capture, challengeID, gateway, method)
}

func (s *Server) BuildReceiptHeader(capture CaptureResult, challengeID string, gateway PaymentGateway, method PaymentMethod) (string, error) {
	if gateway == "" {
		gateway = s.config.PaymentGateway
	}
	return BuildReceiptHeader(capture, challengeID, gateway, method)
}
