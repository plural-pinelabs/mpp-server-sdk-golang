package p3pserver

import (
	"context"
	"net/http"
	"time"
)

type PaymentMethod string

const (
	PaymentMethodReservePay PaymentMethod = "RESERVE_PAY"
	PaymentMethodOTM        PaymentMethod = "OTM"
	PaymentMethodCard       PaymentMethod = "CARD"
	PaymentMethodCreditEMI  PaymentMethod = "CREDIT_EMI"
	PaymentMethodCrypto     PaymentMethod = "CRYPTO"
)

type PaymentGateway string

const PaymentGatewayPineLabsOnline PaymentGateway = "PINE LABS ONLINE"
const GrantexTokenHeader = "X-Grantex-Token"

type Amount struct {
	Value    int64  `json:"value"`
	Currency string `json:"currency"`
}
type Logger interface {
	Debug(string, map[string]interface{})
	Info(string, map[string]interface{})
	Error(string, map[string]interface{})
}
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type GrantexGrant struct {
	GrantID  string                 `json:"grant_id"`
	AgentDID string                 `json:"agent_did"`
	Scopes   []string               `json:"scopes"`
	Claims   map[string]interface{} `json:"-"`
}
type GrantexVerificationResult struct {
	Valid bool
	Grant *GrantexGrant
	Error string
}
type GrantexVerifier interface {
	Verify(context.Context, string) GrantexVerificationResult
}

type HostedGrantexConfig struct {
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	MaxRetries *int
	HTTPClient HTTPDoer
}
type ServerGrantexConfig struct {
	JWKSURI                    string
	RequiredScopes             []string
	Issuer                     string
	IssuerDID                  string
	Audience                   string
	AgentID                    string
	ClockTolerance             time.Duration
	EnforceGrant               bool
	Hosted                     *HostedGrantexConfig
	DebitBudgetBeforeChallenge *bool
	Verifier                   GrantexVerifier
}

type Config struct {
	ClientID                string
	ClientSecret            string
	MerchantID              string
	PaymentGateway          PaymentGateway
	AvailablePaymentMethods []PaymentMethod
	Env                     string
	Realm                   string
	DefaultChallengeExpiry  time.Duration
	RequestTimeout          time.Duration
	MaxRetries              *int
	InitialRetryDelay       time.Duration
	Logger                  Logger
	Grantex                 *ServerGrantexConfig
	HTTPClient              HTTPDoer
}

type ChargeOptions struct {
	Amount                 Amount
	Resource               string
	Description            string
	MerchantOrderReference string
	Metadata               map[string]interface{}
	ChallengeExpiry        time.Duration
}
type ChallengeRequest struct {
	Scheme                  string          `json:"scheme"`
	Amount                  string          `json:"amount"`
	Currency                string          `json:"currency"`
	Resource                string          `json:"resource"`
	AvailablePaymentMethods []PaymentMethod `json:"availablePaymentMethods"`
}
type Challenge struct {
	ID             string           `json:"id"`
	Realm          string           `json:"realm"`
	Intent         string           `json:"intent"`
	Request        ChallengeRequest `json:"request"`
	Expires        string           `json:"expires"`
	PaymentGateway PaymentGateway   `json:"paymentGateway,omitempty"`
}
type ProblemDetails struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Status      int    `json:"status"`
	Detail      string `json:"detail"`
	ChallengeID string `json:"challengeId"`
}
type ChallengeResult struct {
	Challenge      Challenge
	Encoded        string
	ProblemDetails ProblemDetails
}

type CredentialPayload struct {
	Type                     string        `json:"type"`
	Token                    string        `json:"token"`
	PaymentMethod            PaymentMethod `json:"payment_method"`
	PaymentMethodReferenceID string        `json:"payment_method_reference_id,omitempty"`
	CustomerReference        string        `json:"customer_reference,omitempty"`
	MobileNumber             string        `json:"mobile_number,omitempty"`
}
type Credential struct {
	Challenge Challenge         `json:"challenge"`
	Source    string            `json:"source"`
	Payload   CredentialPayload `json:"payload"`
}
type VerificationResult struct {
	Valid      bool
	Credential *Credential
	Error      string
}

type CaptureOptions struct {
	Token                    string
	Amount                   Amount
	PaymentMethod            PaymentMethod
	Description              string
	MerchantOrderReference   string
	Metadata                 map[string]string
	IdempotencyKey           string
	PaymentMethodReferenceID string
	CustomerReference        string
	MobileNumber             string
	ChallengeID              string
}
type CaptureResult struct {
	PaymentMethodReferenceID      string                 `json:"payment_method_reference_id,omitempty"`
	PaymentID                     string                 `json:"payment_id,omitempty"`
	MerchantPaymentDebitReference string                 `json:"merchant_payment_debit_reference,omitempty"`
	MerchantOrderReference        string                 `json:"merchant_order_reference,omitempty"`
	CaptureID                     string                 `json:"capture_id,omitempty"`
	OrderID                       string                 `json:"order_id,omitempty"`
	Status                        string                 `json:"status,omitempty"`
	Amount                        *Amount                `json:"amount,omitempty"`
	SettledAt                     string                 `json:"settled_at,omitempty"`
	PaymentGateway                PaymentGateway         `json:"payment_gateway,omitempty"`
	PaymentMethod                 PaymentMethod          `json:"payment_method,omitempty"`
	IdempotencyKey                string                 `json:"idempotencyKey,omitempty"`
	Pending                       bool                   `json:"pending,omitempty"`
	Message                       string                 `json:"message,omitempty"`
	RetryAfter                    time.Duration          `json:"retryAfter,omitempty"`
	Raw                           map[string]interface{} `json:"-"`
}

type Settlement struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}
type ReceiptData struct {
	Status                 string         `json:"status"`
	Timestamp              string         `json:"timestamp"`
	Reference              string         `json:"reference"`
	ChallengeID            string         `json:"challengeId"`
	Settlement             *Settlement    `json:"settlement,omitempty"`
	PaymentGateway         PaymentGateway `json:"paymentGateway,omitempty"`
	PaymentMethod          PaymentMethod  `json:"paymentMethod,omitempty"`
	OrderID                string         `json:"orderId,omitempty"`
	MerchantOrderReference string         `json:"merchantOrderReference,omitempty"`
}

type CreateMandateOptions struct {
	Amount               Amount
	MobileNumber         string
	CustomerReference    string
	CustomerID           string
	Description          string
	Metadata             map[string]string
	Expiry               string
	IdempotencyKey       string
	PaymentMethod        PaymentMethod
	PaymentMethodOptions map[string]interface{}
	ValidityInDays       int
	MerchantMetadata     map[string]interface{}
}
type CreatePreAuthorizationOptions = CreateMandateOptions
type MandateChallenge struct {
	Type      string `json:"type"`
	QRURL     string `json:"qr_url"`
	DeepLink  string `json:"deep_link"`
	ExpiresAt string `json:"expires_at"`
}
type Mandate struct {
	MandateID         string
	Object            string
	OrderID           string
	OrderStatus       string
	PaymentStatus     string
	CustomerReference string
	CustomerID        string
	AgentID           string
	Amount            Amount
	AmountBlocked     int64
	AmountDebited     int64
	AmountHeld        int64
	AmountAvailable   int64
	MobileNumber      string
	Description       string
	Metadata          map[string]interface{}
	ExpiresAt         string
	CreatedAt         string
	Challenge         *MandateChallenge
	Raw               map[string]interface{}
}
type PreAuthorizationCustomer struct {
	CustomerID                string `json:"customer_id,omitempty"`
	MerchantCustomerReference string `json:"merchant_customer_reference,omitempty"`
	MobileNumber              string `json:"mobile_number"`
}
type PreAuthorization struct {
	PaymentMethod            PaymentMethod
	PaymentMethodReferenceID string
	Customer                 PreAuthorizationCustomer
	Status                   string
	Amount                   Amount
	// ChallengeURL preserves the hosted checkout URL returned as challenge_url.
	ChallengeURL string
	// RedirectURL is the normalized hosted checkout URL. It falls back to
	// challenge_url when the live response omits redirect_url.
	RedirectURL    string
	ValidityInDays int
	ExpiryAt       string
	Raw            map[string]interface{}
}
type MandateBalanceLookupOptions struct {
	AuthorizationID string
	PhoneNumber     string
	PaymentMethod   PaymentMethod
}
type MandateBalanceCustomer struct {
	MobileNumber              string
	MerchantCustomerReference string
	BankAccountNumber         string
}
type MandateBalanceDetails struct {
	AmountDebited   Amount
	AmountRemaining Amount
}
type MandateBalanceResult struct {
	PaymentMethod            PaymentMethod
	PaymentMethodReferenceID string
	MerchantID               string
	Customer                 MandateBalanceCustomer
	Status                   string
	Amount                   *Amount
	Description              string
	ValidityInDays           int
	ExpiryAt                 string
	ChallengeURL             string
	ExternalReferenceID      string
	CreatedAt                string
	BalanceDetails           *MandateBalanceDetails
	Raw                      map[string]interface{}
}
type RevokeMandateCustomerLookup struct {
	MerchantCustomerReference string
	MobileNumber              string
}
type CreateMandateRevokeOptions struct {
	PaymentMethod            PaymentMethod
	PaymentMethodReferenceID string
	Customer                 *RevokeMandateCustomerLookup
}
type MandateRevokeResult struct {
	PaymentMethod            PaymentMethod
	PaymentMethodReferenceID string
	RevokeReferenceID        string
	Status                   string
	Raw                      map[string]interface{}
}

type GrantexAuthorizationOptions struct {
	UserID              string
	AgentID             string
	Scopes              []string
	RedirectURI         string
	ExpiresIn           interface{}
	CodeChallenge       string
	CodeChallengeMethod string
}
type GrantexAuthorizationResult struct {
	AuthRequestID string
	ConsentURL    string
	AgentID       string
	PrincipalID   string
	Scopes        []string
	ExpiresAt     string
	Status        string
	Raw           map[string]interface{}
}
type GrantexExchangeCodeOptions struct {
	Code             string
	AgentID          string
	CodeVerifier     string
	CredentialFormat string
}
type GrantexExchangeCodeResult struct {
	GrantToken   string
	GrantID      string
	RefreshToken string
	Scopes       []string
	ExpiresAt    string
	Raw          map[string]interface{}
}
type GrantexBudgetAllocationOptions struct {
	GrantID       string
	InitialBudget float64
	Currency      string
}
type GrantexBudgetAllocationResult struct {
	ID              string
	GrantID         string
	InitialBudget   float64
	RemainingBudget float64
	Currency        string
	CreatedAt       string
	Raw             map[string]interface{}
}
type GrantexBudgetDebitOptions struct {
	GrantID     string
	Amount      float64
	Description string
	Metadata    map[string]interface{}
}
type GrantexBudgetDebitResult struct {
	GrantID       string
	Remaining     float64
	TransactionID string
	Raw           map[string]interface{}
}
type GrantexBudgetBalanceResult = GrantexBudgetAllocationResult
type GrantexBudgetTransaction struct {
	ID           string
	GrantID      string
	Amount       float64
	Description  string
	BalanceAfter float64
	CreatedAt    string
	Raw          map[string]interface{}
}
type GrantexBudgetTransactionsOptions struct {
	Limit  int
	Cursor string
}
type GrantexBudgetTransactionsResult struct {
	Transactions []GrantexBudgetTransaction
	Total        int
	Raw          map[string]interface{}
}

type Decision struct {
	Action          string
	Status          int
	Headers         http.Header
	ProblemDetails  map[string]interface{}
	PendingBody     map[string]interface{}
	CaptureResult   *CaptureResult
	Credential      *Credential
	ReceiptHeader   string
	ChallengeResult *ChallengeResult
	GrantResult     *GrantexVerificationResult
}
