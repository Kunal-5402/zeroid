package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"

	"github.com/zeroid-dev/zeroid/domain"
	"github.com/zeroid-dev/zeroid/internal/signing"
	"github.com/zeroid-dev/zeroid/internal/store/postgres"
)

// CredentialService handles JWT issuance, rotation, and revocation.
type CredentialService struct {
	repo            *postgres.CredentialRepository
	jwksSvc         *signing.JWKSService
	policySvc       *CredentialPolicyService
	attestationRepo *postgres.AttestationRepository
	issuer          string
	defaultTTL      int
	maxTTL          int
}

// NewCredentialService creates a new CredentialService.
func NewCredentialService(
	repo *postgres.CredentialRepository,
	jwksSvc *signing.JWKSService,
	policySvc *CredentialPolicyService,
	attestationRepo *postgres.AttestationRepository,
	issuer string,
	defaultTTL, maxTTL int,
) *CredentialService {
	return &CredentialService{
		repo:            repo,
		jwksSvc:         jwksSvc,
		policySvc:       policySvc,
		attestationRepo: attestationRepo,
		issuer:          issuer,
		defaultTTL:      defaultTTL,
		maxTTL:          maxTTL,
	}
}

// IssueRequest holds parameters for credential issuance.
// If Scopes is non-empty, they are validated against the identity's AllowedScopes.
// TTL defaults to the service default and is capped at MaxTTL.
type IssueRequest struct {
	Identity           *domain.Identity
	CredentialPolicyID string // From the API key, not the identity.
	Scopes             []string
	TTL                int
	GrantType          domain.GrantType
	Audience           []string
	// DelegatedBy is the WIMSE URI of the orchestrator delegating authority.
	// Set only for token_exchange (RFC 8693) grants.
	DelegatedBy string
	// ParentJTI is the JTI of the orchestrator's credential being exchanged.
	// Used for cascade revocation of delegated credentials.
	ParentJTI string
	// DelegationDepth tracks how deep this credential is in the delegation chain.
	// 0 = direct credential, 1 = first delegation, etc.
	DelegationDepth int
	// UseRS256 requests RS256 signing instead of the default ES256.
	// Set for api_key grant to produce compatible tokens.
	UseRS256 bool
	// ApplicationID is the optional application scope (set when API key is linked to an application).
	ApplicationID string
	// SubjectOverride, when non-empty, replaces the default WIMSE URI as the JWT "sub" claim.
	// Used by api_key grant to set sub = user ID (created_by) instead of WIMSE URI.
	SubjectOverride string
	// UserEmail and UserName are set for human user tokens.
	UserEmail string
	UserName  string
	// CustomClaims allows callers to add arbitrary key-value pairs to the JWT.
	// This is the extensibility hook for deployment-specific claims.
	CustomClaims map[string]any
}

// ErrScopesNotAllowed is returned when one or more requested scopes are not in the identity's AllowedScopes list.
var ErrScopesNotAllowed = fmt.Errorf("one or more requested scopes are not permitted for this identity")

// IssueCredential issues a short-lived JWT for an identity.
func (s *CredentialService) IssueCredential(ctx context.Context, req IssueRequest) (*domain.AccessToken, *domain.IssuedCredential, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	if req.GrantType == "" {
		req.GrantType = domain.GrantTypeClientCredentials
	}

	// Enforce allowed_scopes: if the identity has a non-empty allowed list, requested scopes must be a subset.
	if len(req.Identity.AllowedScopes) > 0 && len(req.Scopes) > 0 {
		allowed := make(map[string]bool, len(req.Identity.AllowedScopes))
		for _, s := range req.Identity.AllowedScopes {
			allowed[s] = true
		}
		for _, requested := range req.Scopes {
			if !allowed[requested] {
				return nil, nil, fmt.Errorf("%w: %q not in allowed_scopes", ErrScopesNotAllowed, requested)
			}
		}
	}

	// Enforce credential policy (all six constraints) if one is assigned to the key.
	if req.CredentialPolicyID != "" && s.policySvc != nil {
		policy, err := s.policySvc.GetPolicy(ctx, req.CredentialPolicyID, req.Identity.AccountID, req.Identity.ProjectID)
		if err != nil {
			return nil, nil, fmt.Errorf("credential policy %s not found: %w", req.CredentialPolicyID, err)
		}

		// Look up the identity's highest verified attestation level for check #5.
		var attestationLevel string
		if s.attestationRepo != nil {
			attestationLevel, _ = s.attestationRepo.GetHighestVerifiedLevel(ctx, req.Identity.ID)
		}

		if err := s.policySvc.EnforcePolicy(ctx, policy, EnforcePolicyRequest{
			TTL:              ttl,
			GrantType:        req.GrantType,
			Scopes:           req.Scopes,
			TrustLevel:       req.Identity.TrustLevel,
			AttestationLevel: attestationLevel,
			DelegationDepth:  req.DelegationDepth,
		}); err != nil {
			log.Warn().
				Err(err).
				Str("identity_id", req.Identity.ID).
				Str("policy_id", req.CredentialPolicyID).
				Msg("Credential policy enforcement denied issuance")
			return nil, nil, err
		}
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	jti := uuid.New().String()

	// Build JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, s.issuer)
	sub := req.Identity.WIMSEURI
	if req.SubjectOverride != "" {
		sub = req.SubjectOverride
	}
	_ = token.Set(jwt.SubjectKey, sub)
	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.ExpirationKey, expiresAt)
	_ = token.Set(jwt.JwtIDKey, jti)
	_ = token.Set("account_id", req.Identity.AccountID)
	_ = token.Set("project_id", req.Identity.ProjectID)
	_ = token.Set("grant_type", string(req.GrantType))

	// Identity claims.
	_ = token.Set("external_id", req.Identity.ExternalID)
	_ = token.Set("identity_type", string(req.Identity.IdentityType))
	_ = token.Set("sub_type", string(req.Identity.SubType))
	_ = token.Set("trust_level", string(req.Identity.TrustLevel))
	_ = token.Set("status", string(req.Identity.Status))

	if req.DelegationDepth > 0 {
		_ = token.Set("delegation_depth", req.DelegationDepth)
	}

	// Identity metadata — embedded so downstream services can
	// make identity-aware decisions without calling back to ZeroID.
	if req.Identity.Name != "" {
		_ = token.Set("name", req.Identity.Name)
	}
	if req.Identity.Framework != "" {
		_ = token.Set("framework", req.Identity.Framework)
	}
	if req.Identity.Version != "" {
		_ = token.Set("version", req.Identity.Version)
	}
	if req.Identity.Publisher != "" {
		_ = token.Set("publisher", req.Identity.Publisher)
	}
	if len(req.Identity.Capabilities) > 0 && string(req.Identity.Capabilities) != "[]" {
		_ = token.Set("capabilities", req.Identity.Capabilities)
	}

	if len(req.Audience) > 0 {
		_ = token.Set(jwt.AudienceKey, req.Audience)
	}
	if len(req.Scopes) > 0 {
		_ = token.Set("scopes", req.Scopes)
	}
	// Generic claims for RS256 tokens (api_key grant).
	if req.ApplicationID != "" {
		_ = token.Set("application_id", req.ApplicationID)
	}
	if req.UserEmail != "" {
		_ = token.Set("user_email", req.UserEmail)
	}
	if req.UserName != "" {
		_ = token.Set("user_name", req.UserName)
	}

	// Custom claims — extensibility hook for deployment-specific data.
	for k, v := range req.CustomClaims {
		_ = token.Set(k, v)
	}

	// For delegated credentials (token_exchange), embed the RFC 8693 "act" claim
	// identifying the orchestrator that granted authority. The "sub" claim remains
	// the actor (sub-agent), so downstream services and authz check the sub-agent's
	// permissions while the audit trail traces back to the delegating orchestrator.
	if req.DelegatedBy != "" {
		_ = token.Set("act", map[string]string{"sub": req.DelegatedBy})
	}

	// Sign: RS256 for api_key grant (compatible), ES256 for all agent/NHI flows.
	var signed []byte
	var signErr error
	if req.UseRS256 && s.jwksSvc.HasRSAKeys() {
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.RS256, s.jwksSvc.RSAPrivateKey()))
	} else {
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.ES256, s.jwksSvc.PrivateKey()))
	}
	if signErr != nil {
		return nil, nil, fmt.Errorf("failed to sign JWT: %w", signErr)
	}

	// Persist credential record
	cred := &domain.IssuedCredential{
		ID:                  uuid.New().String(),
		IdentityID:          stringPtrOrNil(req.Identity.ID),
		AccountID:           req.Identity.AccountID,
		ProjectID:           req.Identity.ProjectID,
		JTI:                 jti,
		Subject:             req.Identity.WIMSEURI,
		IssuedAt:            now,
		ExpiresAt:           expiresAt,
		TTLSeconds:          ttl,
		Scopes:              coalesceScopeSlice(req.Scopes),
		GrantType:           req.GrantType,
		DelegationDepth:     req.DelegationDepth,
		ParentJTI:           req.ParentJTI,
		DelegatedByWIMSEURI: req.DelegatedBy,
	}

	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, nil, fmt.Errorf("failed to persist credential: %w", err)
	}

	log.Info().
		Str("jti", jti).
		Str("identity_id", req.Identity.ID).
		Int("ttl_seconds", ttl).
		Msg("Credential issued")

	accessToken := &domain.AccessToken{
		AccessToken: string(signed),
		TokenType:   "Bearer",
		ExpiresIn:   ttl,
		Scope:       strings.Join(req.Scopes, " "),
		JTI:         jti,
		IssuedAt:    now.Unix(),
	}

	return accessToken, cred, nil
}

// GetCredential retrieves a credential by ID.
func (s *CredentialService) GetCredential(ctx context.Context, id, accountID, projectID string) (*domain.IssuedCredential, error) {
	return s.repo.GetByID(ctx, id, accountID, projectID)
}

// ListCredentials returns credentials for a given identity.
func (s *CredentialService) ListCredentials(ctx context.Context, identityID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	return s.repo.ListByIdentity(ctx, identityID, accountID, projectID)
}

// RevokeCredential revokes a credential by ID.
func (s *CredentialService) RevokeCredential(ctx context.Context, id, accountID, projectID, reason string) error {
	if reason == "" {
		reason = "manual_revocation"
	}
	return s.repo.Revoke(ctx, id, accountID, projectID, reason)
}

// RotateCredential revokes an existing credential and immediately issues a new one for the same identity.
// The new credential inherits the scopes and TTL of the old one unless overridden.
func (s *CredentialService) RotateCredential(ctx context.Context, credID, accountID, projectID string, identity *domain.Identity) (*domain.AccessToken, *domain.IssuedCredential, error) {
	old, err := s.repo.GetByID(ctx, credID, accountID, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("credential not found: %w", err)
	}
	if old.IsRevoked {
		return nil, nil, fmt.Errorf("credential is already revoked")
	}

	// Revoke the old credential.
	if err := s.repo.Revoke(ctx, credID, accountID, projectID, "rotated"); err != nil {
		return nil, nil, fmt.Errorf("failed to revoke old credential during rotation: %w", err)
	}

	// Issue a new one with the same parameters.
	return s.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		Scopes:    old.Scopes,
		TTL:       old.TTLSeconds,
		GrantType: old.GrantType,
	})
}

// coalesceScopeSlice returns an empty slice if scopes is nil (avoids DB NOT NULL violations).
func coalesceScopeSlice(scopes []string) []string {
	if scopes == nil {
		return []string{}
	}
	return scopes
}

// stringPtrOrNil returns a pointer to s if non-empty, or nil (for nullable UUID columns).
func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// IntrospectToken checks the validity of a JTI against the credential store.
func (s *CredentialService) IntrospectToken(ctx context.Context, jti string) (*domain.IssuedCredential, bool, error) {
	cred, err := s.repo.GetByJTI(ctx, jti)
	if err != nil {
		return nil, false, nil // not found = inactive
	}
	if cred.IsRevoked {
		return cred, false, nil
	}
	if time.Now().After(cred.ExpiresAt) {
		return cred, false, nil
	}
	return cred, true, nil
}
