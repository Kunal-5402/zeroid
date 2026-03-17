package service

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// AuthCodeClaims holds the decoded claims from an authorization code JWT.
type AuthCodeClaims struct {
	ClientID      string   // "cid" — Client application ID
	CodeChallenge string   // "cc"  — PKCE code challenge (S256)
	RedirectURI   string   // "ruri" — OAuth redirect URI
	Scopes        []string // "scp" — Granted scopes
	UserID        string   // "uid" — User ID
	OrgID         string   // "oid" — Organization ID
	AccountID     string   // "aid" — Account ID
	ProjectID     string   // "pid" — Project ID (optional)
}

// decodeAuthCodeJWT verifies and decodes a stateless auth code JWT (HS256).
// Auth codes are signed with the shared secret and are short-lived (5 min).
func decodeAuthCodeJWT(code, hmacSecret, expectedIssuer string) (*AuthCodeClaims, error) {
	token, err := jwt.Parse([]byte(code),
		jwt.WithKey(jwa.HS256, []byte(hmacSecret)),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("auth code validation failed: %w", err)
	}

	// Validate issuer and subject.
	if token.Issuer() != expectedIssuer {
		return nil, fmt.Errorf("auth code has invalid issuer: %s", token.Issuer())
	}

	if token.Subject() != "auth-code" {
		return nil, fmt.Errorf("auth code has invalid subject: %s", token.Subject())
	}

	claims := &AuthCodeClaims{
		ClientID:      getStringClaim(token, "cid"),
		CodeChallenge: getStringClaim(token, "cc"),
		RedirectURI:   getStringClaim(token, "ruri"),
		UserID:        getStringClaim(token, "uid"),
		OrgID:         getStringClaim(token, "oid"),
		AccountID:     getStringClaim(token, "aid"),
		ProjectID:     getStringClaim(token, "pid"),
	}

	// Extract scopes array.
	if scopesRaw, ok := token.Get("scp"); ok {
		if scopes, ok := scopesRaw.([]interface{}); ok {
			for _, s := range scopes {
				if str, ok := s.(string); ok {
					claims.Scopes = append(claims.Scopes, str)
				}
			}
		}
	}

	return claims, nil
}

// getStringClaim extracts a string claim from a JWT token, returning empty string if not present.
func getStringClaim(token jwt.Token, key string) string {
	if v, ok := token.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}

	return ""
}

// verifyCodeChallenge verifies the PKCE S256 challenge.
// challenge = base64url(sha256(verifier))
func verifyCodeChallenge(codeVerifier, codeChallenge string) bool {
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	return computed == codeChallenge
}

// normalizeLoopback normalizes loopback URIs per RFC 8252.
// Treats 127.0.0.1 and localhost as equivalent for native app OAuth redirects.
func normalizeLoopback(uri string) string {
	return strings.Replace(uri, "://127.0.0.1:", "://localhost:", 1)
}
