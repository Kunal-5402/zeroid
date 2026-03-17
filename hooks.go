package zeroid

import (
	"context"

	"github.com/zeroid-dev/zeroid/domain"
)

// ClaimsEnricher is called during JWT issuance to add custom claims.
// The claims map already contains standard ZeroID claims; the enricher may add or override entries.
type ClaimsEnricher func(claims map[string]any, identity *domain.Identity, grantType domain.GrantType)

// GrantHandler implements a custom OAuth2 grant type.
// Return a non-nil AccessToken on success. Returning an error causes a 400 response.
type GrantHandler func(ctx context.Context, req map[string]string) (*domain.AccessToken, error)
