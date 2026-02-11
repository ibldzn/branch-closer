package fincloud

import "context"

type contextKey string

const fincloudSessionContextKey contextKey = "fincloud-session-id"

// WithFincloudSessionID stores the Fincloud session identifier on the context.
func WithFincloudSessionID(ctx context.Context, sessionID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, fincloudSessionContextKey, sessionID)
}

// SessionIDFromContext retrieves the Fincloud session identifier from the
// context when present.
func SessionIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	if id, ok := ctx.Value(fincloudSessionContextKey).(string); ok && id != "" {
		return id, true
	}
	return "", false
}
