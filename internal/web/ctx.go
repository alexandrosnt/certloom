package web

import (
	"context"
	"net"
	"net/http"
)

type tokenKey struct{}

func withToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, tokenKey{}, tok)
}

func tokenFrom(ctx context.Context) string { s, _ := ctx.Value(tokenKey{}).(string); return s }

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
