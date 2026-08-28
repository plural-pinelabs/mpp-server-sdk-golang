package p3pserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const DefaultGrantexJWKSURI = "https://api.grantex.dev/.well-known/jwks.json"

// GrantTokenVerifier verifies compact Grantex JWTs against a cached JWKS.
// RS256, ES256, and EdDSA signing keys are supported without external modules.
type GrantTokenVerifier struct {
	config ServerGrantexConfig
	http   HTTPDoer
	mu     sync.Mutex
	keys   map[string]crypto.PublicKey
	loaded time.Time
}

func NewGrantTokenVerifier(config ServerGrantexConfig, client HTTPDoer) *GrantTokenVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	return &GrantTokenVerifier{config: config, http: client}
}

func (v *GrantTokenVerifier) Verify(ctx context.Context, token string) GrantexVerificationResult {
	token = strings.TrimSpace(token)
	if token == "" {
		return invalidGrant("Missing grant token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalidGrant("Grant token must be a compact JWT")
	}
	var header, claims map[string]interface{}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return invalidGrant(err.Error())
	}
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return invalidGrant(err.Error())
	}
	keys, err := v.loadKeys(ctx)
	if err != nil {
		return invalidGrant(err.Error())
	}
	kid, _ := header["kid"].(string)
	key := keys[kid]
	if key == nil && len(keys) == 1 {
		for candidateID, candidate := range keys {
			_ = candidateID
			key = candidate
		}
	}
	if key == nil {
		return invalidGrant("No Grantex JWKS key matches JWT kid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalidGrant("Invalid JWT signature encoding")
	}
	algorithm, _ := header["alg"].(string)
	if err := verifyJWTSignature(algorithm, key, []byte(parts[0]+"."+parts[1]), signature); err != nil {
		return invalidGrant(err.Error())
	}
	if err := validateGrantClaims(claims, v.config); err != nil {
		return invalidGrant(err.Error())
	}
	grant := &GrantexGrant{GrantID: claimString(claims, "grant_id", "grantId", "jti"), AgentDID: claimString(claims, "agent_did", "agentDid", "agent_id", "agentId"), Scopes: claimStrings(claims["scopes"]), Claims: claims}
	if grant.AgentDID == "" {
		grant.AgentDID = claimString(claims, "sub")
	}
	if v.config.AgentID != "" && grant.AgentDID != v.config.AgentID {
		return GrantexVerificationResult{Grant: grant, Error: fmt.Sprintf("Grant agent mismatch. Expected %q, got %q", v.config.AgentID, grant.AgentDID)}
	}
	if missing := MissingGrantScopes(grant.Scopes, v.config.RequiredScopes); len(missing) > 0 {
		return GrantexVerificationResult{Grant: grant, Error: "Grant token is missing required scopes: " + strings.Join(missing, ", ")}
	}
	return GrantexVerificationResult{Valid: true, Grant: grant}
}

func (v *GrantTokenVerifier) loadKeys(ctx context.Context) (map[string]crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) > 0 && time.Since(v.loaded) < 5*time.Minute {
		return v.keys, nil
	}
	uri := strings.TrimSpace(v.config.JWKSURI)
	if uri == "" && v.config.Hosted != nil {
		baseURL := strings.TrimRight(strings.TrimSpace(v.config.Hosted.BaseURL), "/")
		if baseURL == "" {
			baseURL = DefaultHostedGrantexBaseURL
		}
		uri = baseURL + "/.well-known/jwks.json"
	}
	if uri == "" {
		uri = DefaultGrantexJWKSURI
	}
	if !strings.HasPrefix(uri, "https://") {
		req, parseErr := http.NewRequest(http.MethodGet, uri, nil)
		if parseErr != nil || !isLocalHostname(req.URL.Hostname()) {
			return nil, fmt.Errorf("ServerGrantexConfig: jwksUri must use HTTPS")
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Grantex JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch Grantex JWKS: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for index, encoded := range document.Keys {
		var metadata map[string]interface{}
		if json.Unmarshal(encoded, &metadata) != nil {
			continue
		}
		key, keyErr := parseJWK(metadata)
		if keyErr != nil {
			continue
		}
		kid, _ := metadata["kid"].(string)
		if kid == "" {
			kid = fmt.Sprintf("#%d", index)
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("Grantex JWKS contains no supported signing keys")
	}
	v.keys, v.loaded = keys, time.Now()
	return keys, nil
}

func parseJWK(jwk map[string]interface{}) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "RSA":
		n, err := decodeBigInt(jwk["n"])
		if err != nil {
			return nil, err
		}
		eBytes, err := decodeURLString(jwk["e"])
		if err != nil {
			return nil, err
		}
		var exponent uint64
		for _, value := range eBytes {
			exponent = exponent<<8 | uint64(value)
		}
		return &rsa.PublicKey{N: n, E: int(exponent)}, nil
	case "EC":
		curveName, _ := jwk["crv"].(string)
		var curve elliptic.Curve
		switch curveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %s", curveName)
		}
		x, err := decodeBigInt(jwk["x"])
		if err != nil {
			return nil, err
		}
		y, err := decodeBigInt(jwk["y"])
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		curve, _ := jwk["crv"].(string)
		if curve != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %s", curve)
		}
		x, err := decodeURLString(jwk["x"])
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported JWK type %s", kty)
	}
}

func verifyJWTSignature(algorithm string, key crypto.PublicKey, input, signature []byte) error {
	digest := sha256.Sum256(input)
	switch algorithm {
	case "RS256":
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWT algorithm/key mismatch")
		}
		if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("Grant token signature verification failed")
		}
	case "ES256":
		public, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature)%2 != 0 {
			return fmt.Errorf("JWT algorithm/key mismatch")
		}
		half := len(signature) / 2
		if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:half]), new(big.Int).SetBytes(signature[half:])) {
			return fmt.Errorf("Grant token signature verification failed")
		}
	case "EdDSA":
		public, ok := key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(public, input, signature) {
			return fmt.Errorf("Grant token signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported JWT algorithm %s", algorithm)
	}
	return nil
}

func validateGrantClaims(claims map[string]interface{}, config ServerGrantexConfig) error {
	now := time.Now()
	if expires := numericClaim(claims["exp"]); expires > 0 && now.After(time.Unix(expires, 0).Add(config.ClockTolerance)) {
		return fmt.Errorf("Grant token has expired")
	}
	if notBefore := numericClaim(claims["nbf"]); notBefore > 0 && now.Add(config.ClockTolerance).Before(time.Unix(notBefore, 0)) {
		return fmt.Errorf("Grant token is not active yet")
	}
	issuer := claimString(claims, "iss")
	if config.Issuer != "" && issuer != config.Issuer {
		return fmt.Errorf("Grant issuer mismatch")
	}
	if config.IssuerDID != "" && issuer != config.IssuerDID && claimString(claims, "issuer_did", "issuerDid") != config.IssuerDID {
		return fmt.Errorf("Grant issuer DID mismatch")
	}
	if config.Audience != "" {
		found := false
		for _, audience := range claimStrings(claims["aud"]) {
			if audience == config.Audience {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("Grant audience mismatch")
		}
	}
	return nil
}

func HasGrantScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required || strings.HasSuffix(scope, ":*") && strings.HasPrefix(required, strings.TrimSuffix(scope, "*")) {
			return true
		}
	}
	return false
}

func MissingGrantScopes(scopes, required []string) []string {
	var missing []string
	for _, scope := range required {
		if !HasGrantScope(scopes, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

func postValidateGrantResult(result GrantexVerificationResult, config ServerGrantexConfig) GrantexVerificationResult {
	if !result.Valid || result.Grant == nil {
		return result
	}
	if config.AgentID != "" && result.Grant.AgentDID != config.AgentID {
		return GrantexVerificationResult{Grant: result.Grant, Error: fmt.Sprintf("Grant agent mismatch. Expected %q, got %q", config.AgentID, result.Grant.AgentDID)}
	}
	if missing := MissingGrantScopes(result.Grant.Scopes, config.RequiredScopes); len(missing) > 0 {
		return GrantexVerificationResult{Grant: result.Grant, Error: "Grant token is missing required scopes: " + strings.Join(missing, ", ")}
	}
	return result
}

func invalidGrant(message string) GrantexVerificationResult {
	return GrantexVerificationResult{Error: message}
}

func decodeJWTPart(value string, target interface{}) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func decodeURLString(value interface{}) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid JWK value")
	}
	return base64.RawURLEncoding.DecodeString(text)
}

func decodeBigInt(value interface{}) (*big.Int, error) {
	raw, err := decodeURLString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func claimString(claims map[string]interface{}, keys ...string) string {
	return firstString(claims, keys...)
}

func claimStrings(value interface{}) []string {
	switch values := value.(type) {
	case string:
		return strings.Fields(values)
	case []interface{}:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return values
	default:
		return nil
	}
}

func numericClaim(value interface{}) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case json.Number:
		result, _ := number.Int64()
		return result
	case int64:
		return number
	case string:
		result, _ := new(big.Int).SetString(number, 10)
		if result != nil {
			return result.Int64()
		}
	}
	return 0
}
