// Package middleware provides HTTP middleware for tenant context extraction
// and authentication for the ZeroID service.
package middleware

import (
	"context"
	"fmt"
)

// TenantContext holds the account and project scope extracted from request headers.
// It is set by TenantContextMiddleware and AgentAuthMiddleware, and retrieved via GetTenant.
type TenantContext struct {
	AccountID string
	ProjectID string
}

type contextKey string

const TenantContextKey contextKey = "tenant"

// GetTenant extracts tenant context from the request context.
func GetTenant(ctx context.Context) (TenantContext, error) {
	tenant, ok := ctx.Value(TenantContextKey).(TenantContext)
	if !ok {
		return TenantContext{}, fmt.Errorf("tenant context not found in request - authentication may have failed")
	}
	if tenant.AccountID == "" {
		return TenantContext{}, fmt.Errorf("tenant context has empty account ID")
	}
	if tenant.ProjectID == "" {
		return TenantContext{}, fmt.Errorf("tenant context has empty project ID")
	}
	return tenant, nil
}

// SetTenant stores tenant context in the request context.
func SetTenant(ctx context.Context, accountID, projectID string) context.Context {
	return context.WithValue(ctx, TenantContextKey, TenantContext{
		AccountID: accountID,
		ProjectID: projectID,
	})
}
