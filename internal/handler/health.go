package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// ── Health types ─────────────────────────────────────────────────────────────

type HealthOutput struct {
	Body struct {
		Status    string    `json:"status" doc:"Service status"`
		Service   string    `json:"service" doc:"Service name"`
		Timestamp time.Time `json:"timestamp" doc:"Current server time"`
		UptimeMs  int64     `json:"uptime_ms" doc:"Uptime in milliseconds"`
	}
}

type ReadyOutput struct {
	Body struct {
		Ready bool   `json:"ready" doc:"Whether the service is ready"`
		Error string `json:"error,omitempty" doc:"Error if not ready"`
	}
}

// ── Health routes ────────────────────────────────────────────────────────────

func (a *API) registerHealthRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Health check",
		Tags:        []string{"Health"},
	}, a.healthOp)

	huma.Register(api, huma.Operation{
		OperationID: "ready",
		Method:      http.MethodGet,
		Path:        "/ready",
		Summary:     "Readiness check (verifies database connectivity)",
		Tags:        []string{"Health"},
	}, a.readyOp)
}

func (a *API) healthOp(_ context.Context, _ *struct{}) (*HealthOutput, error) {
	out := &HealthOutput{}
	out.Body.Status = "healthy"
	out.Body.Service = "zeroid"
	out.Body.Timestamp = time.Now().UTC()
	out.Body.UptimeMs = time.Since(a.startTime).Milliseconds()
	return out, nil
}

func (a *API) readyOp(ctx context.Context, _ *struct{}) (*ReadyOutput, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := a.db.PingContext(checkCtx); err != nil {
		return nil, huma.Error503ServiceUnavailable("database unreachable")
	}

	out := &ReadyOutput{}
	out.Body.Ready = true
	return out, nil
}
