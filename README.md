# Pine Labs Online MPP Server SDK for Go

Go server SDK equivalent to `mpp-server-sdk-python-main`. It creates mandates,
signs HTTP 402 Payment challenges, verifies client credentials, captures
payments, and produces `Payment-Receipt` headers.

The module uses only the Go standard library and supports Go 1.22 or newer.

## Install

```bash
go get github.com/pine-labs-online/p3p-server-sdk-go
```

```go
import p3pserver "github.com/pine-labs-online/p3p-server-sdk-go"
```

## Configure

```go
server, err := p3pserver.New(p3pserver.Config{
	Env:                     p3pserver.EnvironmentSandbox,
	ClientID:                "client-id",
	ClientSecret:            "client-secret",
	MerchantID:              "merchant-id",
	PaymentGateway:          p3pserver.PaymentGatewayPineLabsOnline,
	AvailablePaymentMethods: []p3pserver.PaymentMethod{
		p3pserver.PaymentMethodReservePay,
		p3pserver.PaymentMethodOTM,
		p3pserver.PaymentMethodCard,
		p3pserver.PaymentMethodCreditEMI,
	},
})
if err != nil {
	panic(err)
}
```

`ClientID`, `ClientSecret`, and `MerchantID` are mandatory. Bearer tokens are
cached, and `Merchant-ID` is sent on mandate, balance, revoke, capture, and
debit-status requests.

## Protect a net/http handler

```go
charge := p3pserver.ChargeOptions{
	Amount:   p3pserver.Amount{Value: 50000, Currency: "INR"},
	Resource: "/api/premium",
}

paid := server.Middleware(charge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":"premium content"}`))
}))
```

The middleware returns a signed 402 challenge when no credential is present,
reads `P3P-Credential: Payment <payload>` (with `Authorization` as a backwards
compatible fallback), verifies its realm, expiry, HMAC, and selected payment
method, captures the payment, and adds `Payment-Receipt` before calling the
protected handler.

Use `MiddlewareFunc` for request-specific pricing, or call `DecidePayment`
directly from any other Go framework.

## Mandate and pre-authorization APIs

```go
preAuth, err := server.CreatePreAuthorization(ctx, p3pserver.CreatePreAuthorizationOptions{
	PaymentMethod: p3pserver.PaymentMethodCreditEMI,
	MobileNumber:  customerMobile,
	Amount:        p3pserver.Amount{Value: orderAmountPaise, Currency: "INR"},
	ValidityInDays: 7,
	MerchantMetadata: map[string]interface{}{
		"p3p_offer_required": "true",
		"offer_data":        selectedOffer,
	},
})
```

Structured merchant metadata is JSON-serialized into Pine's string-valued
wire map. `CREDIT_EMI` is preserved as `payment_method: "CREDIT_EMI"` in the
`/mpp/v1/pre-authorize` request; the SDK never changes it to `CARD`.

Live pre-authorization responses may contain `challenge_url` without
`redirect_url`. `PreAuthorization.ChallengeURL` preserves that value and
`PreAuthorization.RedirectURL` normalizes it as the hosted checkout URL, so a
successful response is never rejected only because `redirect_url` is absent.
`PreAuthorization.Raw` retains the exact upstream response shape.

The module also exposes `CreateMandate`, `GetMandate`, `GetMandateBalance`,
and `RevokeMandate`.

## Capture and pending debit safety

```go
result, err := server.Capture(ctx, p3pserver.CaptureOptions{
	Token:          "MPP_TOK_123",
	Amount:         p3pserver.Amount{Value: 50000, Currency: "INR"},
	PaymentMethod:  p3pserver.PaymentMethodReservePay,
	MobileNumber:   "9876543210",
	ChallengeID:    "ch_...",
	IdempotencyKey: "order-123",
})
```

When `POST /mpp/v1/debit` returns 202, the SDK never re-POSTs the accepted
debit. It polls only `GET /mpp/v1/debit/{idempotency-key}`, respects
`Retry-After`, and returns a pending result if the poll budget is exhausted.
Use `GetDebitStatus` to reconcile it later.

## Grantex

Offline grant verification supports JWKS caching, RS256, ES256, EdDSA,
issuer/audience/agent checks, required scopes, wildcard scopes, and the
`mpp:payment:max_txn_paise:<amount>` transaction cap.

Hosted APIs are available through `CreateGrantexAuthorization`,
`ExchangeGrantexCode`, `AllocateGrantexBudget`, `DebitGrantexBudget`,
`GetGrantexBudgetBalance`, and `ListGrantexBudgetTransactions`. Hosted calls
use Bearer API-key authentication and retry transient responses.

## Test

```bash
go test -race ./...
go vet ./...
```

## License

MIT
