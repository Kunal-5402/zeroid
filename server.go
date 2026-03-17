package zeroid

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojson "github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/zeroid-dev/zeroid/domain"
	"github.com/zeroid-dev/zeroid/internal/database"
	"github.com/zeroid-dev/zeroid/internal/handler"
	internalMiddleware "github.com/zeroid-dev/zeroid/internal/middleware"
	"github.com/zeroid-dev/zeroid/internal/service"
	"github.com/zeroid-dev/zeroid/internal/signing"
	"github.com/zeroid-dev/zeroid/internal/store/postgres"
	"github.com/zeroid-dev/zeroid/internal/telemetry"
	"github.com/zeroid-dev/zeroid/internal/worker"
)

// Server is the main ZeroID server. It holds all dependencies and exposes
// the chi router for custom route mounting.
type Server struct {
	cfg    Config
	db     *bun.DB
	router chi.Router
	http   *http.Server

	// Services
	identitySvc         *service.IdentityService
	credentialSvc       *service.CredentialService
	credentialPolicySvc *service.CredentialPolicyService
	attestationSvc      *service.AttestationService
	proofSvc            *service.ProofService
	oauthSvc            *service.OAuthService
	oauthClientSvc      *service.OAuthClientService
	signalSvc           *service.SignalService
	apiKeySvc           *service.APIKeyService
	agentSvc            *service.AgentService
	jwksSvc             *signing.JWKSService
	refreshTokenSvc     *service.RefreshTokenService

	// Cleanup
	cleanupWorker *worker.CleanupWorker
	workerCancel  context.CancelFunc

	// Extensibility
	mu              sync.RWMutex
	customGrants    map[string]GrantHandler
	claimsEnrichers []ClaimsEnricher
}

// NewServer initializes all ZeroID subsystems: database, migrations, signing keys,
// repositories, services, handlers, and the HTTP router.
func NewServer(cfg Config) (*Server, error) {
	initLogging(cfg.Logging.Level)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	log.Info().Msg("Initializing ZeroID server")

	// Initialize OpenTelemetry.
	if err := telemetry.Init(telemetry.Config{
		Enabled:      cfg.Telemetry.Enabled,
		Endpoint:     cfg.Telemetry.Endpoint,
		Insecure:     cfg.Telemetry.Insecure,
		ServiceName:  cfg.Telemetry.ServiceName,
		SamplingRate: cfg.Telemetry.SamplingRate,
	}); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize telemetry — continuing without observability")
	}

	// Initialize database.
	db, err := initDatabase(cfg.Database.URL, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Run migrations.
	if err := database.RunMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	// Initialize JWKS service (loads ECDSA P-256 key pair).
	jwksSvc, err := signing.NewJWKSService(cfg.Keys.PrivateKeyPath, cfg.Keys.PublicKeyPath, cfg.Keys.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS service — run 'make setup-keys': %w", err)
	}

	// Load RSA keys for RS256 signing (optional — required for api_key grant).
	if cfg.Keys.RSAPrivateKeyPath != "" && cfg.Keys.RSAPublicKeyPath != "" {
		if err := jwksSvc.LoadRSAKeys(cfg.Keys.RSAPrivateKeyPath, cfg.Keys.RSAPublicKeyPath, cfg.Keys.RSAKeyID); err != nil {
			return nil, fmt.Errorf("failed to load RSA keys for RS256 signing: %w", err)
		}
	} else {
		log.Info().Msg("RSA keys not configured — api_key grant type will be unavailable")
	}

	// Initialize repositories.
	identityRepo := postgres.NewIdentityRepository(db)
	credentialRepo := postgres.NewCredentialRepository(db)
	attestationRepo := postgres.NewAttestationRepository(db)
	signalRepo := postgres.NewSignalRepository(db)
	proofRepo := postgres.NewProofRepository(db)
	oauthClientRepo := postgres.NewOAuthClientRepository(db)
	credentialPolicyRepo := postgres.NewCredentialPolicyRepository(db)
	apiKeyRepo := postgres.NewAPIKeyRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(db)

	// Initialize services.
	identitySvc := service.NewIdentityService(identityRepo, cfg.WIMSEDomain)
	credentialPolicySvc := service.NewCredentialPolicyService(credentialPolicyRepo)
	credentialSvc := service.NewCredentialService(credentialRepo, jwksSvc, credentialPolicySvc, attestationRepo, cfg.Token.Issuer, cfg.Token.DefaultTTL, cfg.Token.MaxTTL)
	attestationSvc := service.NewAttestationService(attestationRepo, credentialSvc, identitySvc)
	oauthClientSvc := service.NewOAuthClientService(oauthClientRepo)
	apiKeySvc := service.NewAPIKeyService(apiKeyRepo, credentialPolicySvc, identitySvc)
	agentSvc := service.NewAgentService(identitySvc, apiKeySvc, apiKeyRepo)
	refreshTokenSvc := service.NewRefreshTokenService(refreshTokenRepo, db)
	oauthSvc := service.NewOAuthService(credentialSvc, identitySvc, oauthClientSvc, apiKeyRepo, jwksSvc, refreshTokenSvc, service.OAuthServiceConfig{
		Issuer:      cfg.Token.Issuer,
		WIMSEDomain: cfg.WIMSEDomain,
		HMACSecret:  cfg.ManagementAPIKey,
	})
	proofSvc := service.NewProofService(jwksSvc, proofRepo, cfg.Token.Issuer)
	signalSvc := service.NewSignalService(signalRepo, credentialRepo)

	// Build router with middleware stack.
	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(requestValidationMiddleware)
	r.Use(errorRecoveryMiddleware)
	r.Use(structuredLoggingMiddleware)
	r.Use(chimiddleware.Recoverer)

	// Create API handler.
	apiHandler := handler.NewAPI(
		identitySvc, credentialSvc, credentialPolicySvc,
		attestationSvc, proofSvc, oauthSvc, oauthClientSvc,
		signalSvc, apiKeySvc, agentSvc, jwksSvc, db,
		cfg.Token.Issuer, cfg.Token.BaseURL,
	)

	// Public routes (no auth).
	humaPublic := handler.NewHumaAPI(r)
	apiHandler.RegisterPublic(humaPublic)

	// Protected routes (management API key auth).
	managementCfg := internalMiddleware.ManagementAuthConfig{}
	if cfg.ManagementAPIKey != "" {
		apiKey := cfg.ManagementAPIKey
		managementCfg.ValidateKey = func(credential string) (string, bool) {
			if credential == apiKey {
				return "management", true
			}
			return "", false
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(internalMiddleware.ManagementAuthMiddleware(managementCfg))

		humaProtected := handler.NewHumaAPI(r)
		apiHandler.RegisterProtected(humaProtected, r)

		// Agent-auth for proof generation.
		r.Group(func(r chi.Router) {
			agentAuthCfg := internalMiddleware.AgentAuthConfig{
				PublicKey: jwksSvc.PublicKey(),
				Issuer:    cfg.Token.Issuer,
			}
			r.Use(internalMiddleware.AgentAuthMiddleware(agentAuthCfg))

			humaAgentAuth := handler.NewHumaAPI(r)
			apiHandler.RegisterAgentAuth(humaAgentAuth)
		})
	})

	// Parse timeouts.
	readTimeout, _ := time.ParseDuration(cfg.Server.ReadTimeout)
	if readTimeout == 0 {
		readTimeout = 15 * time.Second
	}
	writeTimeout, _ := time.ParseDuration(cfg.Server.WriteTimeout)
	if writeTimeout == 0 {
		writeTimeout = 15 * time.Second
	}
	idleTimeout, _ := time.ParseDuration(cfg.Server.IdleTimeout)
	if idleTimeout == 0 {
		idleTimeout = 60 * time.Second
	}

	srv := &Server{
		cfg:                 cfg,
		db:                  db,
		router:              r,
		identitySvc:         identitySvc,
		credentialSvc:       credentialSvc,
		credentialPolicySvc: credentialPolicySvc,
		attestationSvc:      attestationSvc,
		proofSvc:            proofSvc,
		oauthSvc:            oauthSvc,
		oauthClientSvc:      oauthClientSvc,
		signalSvc:           signalSvc,
		apiKeySvc:           apiKeySvc,
		agentSvc:            agentSvc,
		jwksSvc:             jwksSvc,
		refreshTokenSvc:     refreshTokenSvc,
		cleanupWorker:       worker.NewCleanupWorker(db, time.Hour),
		customGrants:        make(map[string]GrantHandler),
		http: &http.Server{
			Addr:         ":" + cfg.Server.Port,
			Handler:      r,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}

	return srv, nil
}

// Start starts the HTTP server and background workers. It blocks until a
// SIGINT/SIGTERM is received and then performs graceful shutdown.
func (s *Server) Start() error {
	// Start background workers.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	s.workerCancel = workerCancel
	go s.cleanupWorker.Run(workerCtx)

	// Start HTTP server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("port", s.cfg.Server.Port).Msg("Starting ZeroID HTTP server")
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or server error.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		s.workerCancel()
		return fmt.Errorf("server error: %w", err)
	case <-sigChan:
		log.Info().Msg("Shutdown signal received, shutting down gracefully...")
	}

	// Graceful shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Server.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	log.Info().Msg("Server shutdown complete")
	return nil
}

// Shutdown gracefully stops the server, workers, database, and telemetry.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.workerCancel != nil {
		s.workerCancel()
	}

	var firstErr error
	if err := s.http.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := s.db.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	telCtx, telCancel := context.WithTimeout(ctx, 5*time.Second)
	defer telCancel()
	if err := telemetry.Shutdown(telCtx); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// RegisterGrant registers a custom OAuth2 grant type handler.
func (s *Server) RegisterGrant(name string, handler GrantHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customGrants[name] = handler
}

// OnClaimsIssue registers a claims enricher called during JWT issuance.
func (s *Server) OnClaimsIssue(enricher ClaimsEnricher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimsEnrichers = append(s.claimsEnrichers, enricher)
}

// Router returns the chi.Router for custom route mounting.
func (s *Server) Router() chi.Router {
	return s.router
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

func initLogging(logLevel string) {
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = log.With().Caller().Logger()
}

func initDatabase(databaseURL string, maxOpenConns, maxIdleConns int) (*bun.DB, error) {
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))

	if err := sqldb.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	sqldb.SetMaxOpenConns(maxOpenConns)
	sqldb.SetMaxIdleConns(maxIdleConns)
	sqldb.SetConnMaxLifetime(30 * time.Minute)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)

	db := bun.NewDB(sqldb, pgdialect.New())

	if parsedURL, err := url.Parse(databaseURL); err == nil {
		log.Info().Str("host", parsedURL.Host).Str("database", parsedURL.Path).Msg("Database connection established")
	}

	return db, nil
}

// errorRecoveryMiddleware recovers from panics and returns a 500 JSON error response.
func errorRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Interface("panic", err).
					Str("method", r.Method).
					Str("path", r.RequestURI).
					Msg("Panic recovered in request handler")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				errResp := domain.NewErrorResponse(
					http.StatusInternalServerError,
					domain.ErrCodeInternal,
					"Internal service error",
				)

				if reqID := chimiddleware.GetReqID(r.Context()); reqID != "" {
					errResp.WithRequestID(reqID)
				}

				_ = gojson.NewEncoder(w).Encode(errResp)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestValidationMiddleware limits request body size to 10 MiB and enforces
// application/json Content-Type on mutating requests (POST, PUT, PATCH).
func requestValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxBodySize = 10 * 1024 * 1024
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			// Allow missing Content-Type for SSE stream endpoint.
			if ct == "" && r.URL.Path != "/api/v1/signals/stream" {
				writeValidationError(w, r, "Content-Type header is required for "+r.Method+" requests")
				return
			}
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				writeValidationError(w, r, "Content-Type must be application/json, got: "+ct)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// writeValidationError writes a 400 JSON error for request-validation failures.
func writeValidationError(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	errResp := map[string]any{
		"error": map[string]any{
			"code":         http.StatusBadRequest,
			"internalCode": domain.ErrCodeBadRequest,
			"message":      msg,
			"status":       "BAD_REQUEST",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		},
	}
	if reqID := chimiddleware.GetReqID(r.Context()); reqID != "" {
		errResp["error"].(map[string]any)["requestId"] = reqID
	}
	_ = gojson.NewEncoder(w).Encode(errResp)
}

// structuredLoggingMiddleware emits zerolog request/response log events.
// Requests taking longer than 1 s are logged at WARN level; 4xx/5xx at ERROR level.
func structuredLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := chimiddleware.GetReqID(r.Context())

		log.Info().
			Str("request_id", requestID).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Str("remote_addr", r.RemoteAddr).
			Msg("request.start")

		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		duration := time.Since(start)
		logLevel := log.Info()
		if duration > time.Second {
			logLevel = log.Warn()
		}
		if ww.Status() >= 400 {
			logLevel = log.Error()
		}

		logLevel.
			Str("request_id", requestID).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Int("status", ww.Status()).
			Dur("duration", duration).
			Msg("request.complete")
	})
}
