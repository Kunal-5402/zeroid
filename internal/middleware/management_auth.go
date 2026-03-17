package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

type managementAuthContextKey string

const (
	HeaderAPIKey    = "X-API-Key"
	HeaderProjectID = "X-Project-ID"
	HeaderAccountID = "X-Account-ID"
	HeaderUserID    = "X-User-ID"

	AuthenticatedNameContextKey managementAuthContextKey = "authenticated_name"
)

// ManagementAuthConfig holds configuration for management API authentication.
type ManagementAuthConfig struct {
	// ValidateKey is a callback that validates an API key or Bearer token and returns
	// the authenticated identity name (e.g., "admin", "studio", or the key name).
	// If nil, any non-empty credential is accepted (development mode only).
	ValidateKey func(credential string) (name string, ok bool)
}

// ManagementAuthMiddleware handles management API authentication.
// It accepts either X-API-Key header or Authorization: Bearer header for authentication,
// and extracts X-Account-ID / X-Project-ID headers for tenant context.
func ManagementAuthMiddleware(cfg ManagementAuthConfig) func(http.Handler) http.Handler {
	if cfg.ValidateKey == nil {
		log.Warn().Msg("Management auth middleware: no key validator configured - running in development mode (insecure)")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract credential from X-API-Key or Authorization: Bearer.
			credential := r.Header.Get(HeaderAPIKey)
			if credential == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					credential = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if credential == "" {
				http.Error(w, "Unauthorized: missing API key or Bearer token", http.StatusUnauthorized)
				return
			}

			// Validate the credential.
			var authenticatedName string
			if cfg.ValidateKey != nil {
				name, ok := cfg.ValidateKey(credential)
				if !ok {
					log.Warn().Msg("Management API call with invalid credentials")
					http.Error(w, "Unauthorized: invalid credentials", http.StatusUnauthorized)
					return
				}
				authenticatedName = name
			} else {
				// Development mode: accept any non-empty credential.
				authenticatedName = "dev"
			}

			projectID := r.Header.Get(HeaderProjectID)
			accountID := r.Header.Get(HeaderAccountID)

			// Tenant headers are optional — some endpoints (e.g., /identities/schema)
			// are tenant-agnostic. Handlers that require tenant context call GetTenant()
			// which returns an error if not set.
			if projectID != "" && accountID != "" {
				ctx = SetTenant(ctx, accountID, projectID)
			}
			ctx = SetAuthenticatedName(ctx, authenticatedName)

			userID := r.Header.Get(HeaderUserID)
			if userID != "" {
				ctx = context.WithValue(ctx, managementAuthContextKey("management_auth_user"), userID)
			}

			log.Debug().
				Str("authenticated_as", authenticatedName).
				Str("project_id", projectID).
				Str("account_id", accountID).
				Msg("Management API call authenticated")

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// SetAuthenticatedName marks the request as coming from an authenticated management caller.
func SetAuthenticatedName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, AuthenticatedNameContextKey, name)
}

// IsAuthenticated checks if the request is from an authenticated management caller.
func IsAuthenticated(ctx context.Context) bool {
	name, ok := ctx.Value(AuthenticatedNameContextKey).(string)
	return ok && name != ""
}

// GetAuthenticatedName returns the name of the authenticated caller, or empty string.
func GetAuthenticatedName(ctx context.Context) string {
	name, _ := ctx.Value(AuthenticatedNameContextKey).(string)
	return name
}
