package middleware

import (
	"context"
	"net/http"
)

type adminContextKey string

const (
	HeaderProjectID = "X-Project-ID"
	HeaderAccountID = "X-Account-ID"
	HeaderUserID    = "X-User-ID"

	callerNameKey adminContextKey = "caller_name"
)

// TenantContextMiddleware extracts tenant context (X-Account-ID, X-Project-ID)
// and optional caller identity (X-User-ID) from request headers into the context.
//
// This middleware performs NO authentication — the admin API is protected at the
// network layer (separate port, not exposed externally). Authentication is the
// operator's responsibility (VPN, service mesh, reverse proxy, or the optional
// AdminAuthMiddleware hook).
func TenantContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accountID := r.Header.Get(HeaderAccountID)
		projectID := r.Header.Get(HeaderProjectID)

		if accountID != "" && projectID != "" {
			ctx = SetTenant(ctx, accountID, projectID)
		}

		userID := r.Header.Get(HeaderUserID)
		if userID != "" {
			ctx = SetCallerName(ctx, userID)
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// SetCallerName records who is making the admin API call (for audit trails).
func SetCallerName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, callerNameKey, name)
}

// GetCallerName returns the caller identity from context, or empty string.
func GetCallerName(ctx context.Context) string {
	name, _ := ctx.Value(callerNameKey).(string)
	return name
}
