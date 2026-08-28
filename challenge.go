package p3pserver

import (
	"fmt"
	"time"
)

func (s *Server) GenerateChallenge(options ChargeOptions) (ChallengeResult, error) {
	if options.Amount.Value <= 0 {
		return ChallengeResult{}, fmt.Errorf("ChargeOptions: amount.value must be a positive integer (paise)")
	}
	expiry := options.ChallengeExpiry
	if expiry == 0 {
		expiry = s.config.DefaultChallengeExpiry
	}
	expires := time.Now().UTC().Add(expiry).Format("2006-01-02T15:04:05.000Z")
	request := ChallengeRequest{Scheme: "exact", Amount: fmt.Sprintf("%.2f", float64(options.Amount.Value)/100), Currency: options.Amount.Currency, Resource: options.Resource, AvailablePaymentMethods: append([]PaymentMethod(nil), s.config.AvailablePaymentMethods...)}
	requestEncoded, err := EncodeJSON(request)
	if err != nil {
		return ChallengeResult{}, err
	}
	challenge := Challenge{ID: computeChallengeID(deriveChallengeHMACKey(s.config.ClientSecret), s.config.Realm, "charge", requestEncoded, expires), Realm: s.config.Realm, Intent: "charge", Request: request, Expires: expires}
	encoded, err := EncodeJSON(challenge)
	if err != nil {
		return ChallengeResult{}, err
	}
	problem := ProblemDetails{Type: s.config.Realm + "/errors/payment-required", Title: "Payment Required", Status: 402, Detail: fmt.Sprintf("This resource requires payment of %s %s", request.Amount, request.Currency), ChallengeID: challenge.ID}
	return ChallengeResult{Challenge: challenge, Encoded: encoded, ProblemDetails: problem}, nil
}
