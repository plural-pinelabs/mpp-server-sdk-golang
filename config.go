package p3pserver

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	EnvironmentSandbox    = "https://pluraluat.v2.pinepg.in"
	EnvironmentProduction = "https://api.pluralpay.in"
)

func normalizeConfig(config Config) (Config, error) {
	if strings.TrimSpace(config.ClientID) == "" {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: clientId is required and must be a non-empty string")
	}
	if strings.TrimSpace(config.ClientSecret) == "" {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: clientSecret is required and must be a non-empty string")
	}
	if strings.TrimSpace(config.MerchantID) == "" {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: merchantId is required and must be a non-empty string")
	}
	if config.PaymentGateway != PaymentGatewayPineLabsOnline {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: paymentGateway must be PaymentGatewayPineLabsOnline")
	}
	if len(config.AvailablePaymentMethods) == 0 {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: availablePaymentMethods must contain at least one payment method")
	}
	for _, method := range config.AvailablePaymentMethods {
		if !isSupportedPaymentMethod(method) {
			return Config{}, unsupportedPaymentMethodError("PineLabsOnlineServerConfig: availablePaymentMethods", method)
		}
	}
	if config.Env == "" {
		config.Env = EnvironmentProduction
	}
	baseURL, err := ResolveBaseURL(config.Env)
	if err != nil {
		return Config{}, err
	}
	config.Env = baseURL
	if config.Realm == "" {
		config.Realm = config.Env
	}
	if config.DefaultChallengeExpiry == 0 {
		config.DefaultChallengeExpiry = 5 * time.Minute
	}
	if config.RequestTimeout == 0 {
		if config.Env == EnvironmentProduction {
			config.RequestTimeout = 45 * time.Second
		} else {
			config.RequestTimeout = 60 * time.Second
		}
	}
	if config.InitialRetryDelay == 0 {
		if config.Env == EnvironmentProduction {
			config.InitialRetryDelay = 200 * time.Millisecond
		} else {
			config.InitialRetryDelay = 300 * time.Millisecond
		}
	}
	if config.MaxRetries == nil {
		value := 2
		config.MaxRetries = &value
	}
	if *config.MaxRetries < 0 {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: maxRetries must be non-negative")
	}
	if config.Grantex != nil && config.Grantex.EnforceGrant && (config.Grantex.Hosted == nil || strings.TrimSpace(config.Grantex.Hosted.APIKey) == "") {
		return Config{}, fmt.Errorf("PineLabsOnlineServerConfig: grantex.hosted.apiKey is required when grantex.enforceGrant is true")
	}
	return config, nil
}

func ResolveBaseURL(value string) (string, error) {
	u, err := url.Parse(value)
	if err == nil && u.Hostname() != "" && (u.Scheme == "https" || u.Scheme == "http" && isLocalHostname(u.Hostname())) {
		return strings.TrimRight(value, "/"), nil
	}
	return "", fmt.Errorf("env must be EnvironmentSandbox, EnvironmentProduction, or an HTTP URL")
}
func isLocalHostname(host string) bool {
	host = strings.Trim(host, "[]")
	parsed := net.ParseIP(host)
	return host == "localhost" || host == "host.docker.internal" || (parsed != nil && parsed.IsLoopback()) || (host != "" && !strings.Contains(host, "."))
}
func isSupportedPaymentMethod(value PaymentMethod) bool {
	switch value {
	case PaymentMethodReservePay, PaymentMethodOTM, PaymentMethodCard, PaymentMethodCreditEMI:
		return true
	}
	return false
}
func unsupportedPaymentMethodError(context string, value PaymentMethod) error {
	if value == PaymentMethodCrypto {
		return fmt.Errorf("%s: PaymentMethodCrypto is currently not supported in SDKs", context)
	}
	return fmt.Errorf("%s: payment method must be RESERVE_PAY, OTM, CARD, or CREDIT_EMI", context)
}
func normalizeMobile(value string) (string, error) {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(value, "")
	if len(digits) > 10 {
		return "", fmt.Errorf("mobileNumber must be at most 10 digits, got %d", len(digits))
	}
	return digits, nil
}

func validateMandateOptions(options CreateMandateOptions) error {
	mobile, err := normalizeMobile(options.MobileNumber)
	if err != nil {
		return err
	}
	if len(mobile) != 10 {
		return fmt.Errorf("CreateMandateOptions: mobileNumber must be 10 digits or E.164 format")
	}
	if options.Amount.Value < 100 {
		return fmt.Errorf("CreateMandateOptions: amount.value must be at least 100 paise")
	}
	if options.Amount.Currency != "INR" {
		return fmt.Errorf("CreateMandateOptions: only INR currency is supported")
	}
	if options.ValidityInDays < 0 {
		return fmt.Errorf("CreateMandateOptions: validityInDays must be a positive integer")
	}
	if options.PaymentMethod != "" && !isSupportedPaymentMethod(options.PaymentMethod) {
		return unsupportedPaymentMethodError("CreateMandateOptions: paymentMethod", options.PaymentMethod)
	}
	return nil
}
