package context

import (
	"context"
	"net"
	"strings"

	"github.com/dwikynator/core-auth/internal/libs/crypto"
	"github.com/dwikynator/minato/merr"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// requestMeta holds per-request transport metadata used for session creation.
type requestMeta struct {
	IPAddress *string
	UserAgent string
}

// metaFromContext extracts IP and User-Agent from gRPC metadata.
// In gateway mode, the grpc-gateway forwards these as metadata keys.
func MetaFromContext(ctx context.Context) requestMeta {
	var meta requestMeta

	// IP address: grpc-gateway sets x-forwarded-for, or we fall back to peer address.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-forwarded-for"); len(vals) > 0 && vals[0] != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			parts := strings.Split(vals[0], ",")
			ip := strings.TrimSpace(parts[0])
			meta.IPAddress = &ip
		}
		if vals := md.Get("grpcgateway-user-agent"); len(vals) > 0 {
			meta.UserAgent = vals[0]
		} else if vals := md.Get("user-agent"); len(vals) > 0 {
			meta.UserAgent = vals[0]
		}
	}

	// Fallback: direct gRPC peer address.
	if meta.IPAddress == nil {
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			addr := p.Addr.String()
			// Strip port from "ip:port" format.
			if host, _, err := net.SplitHostPort(addr); err == nil {
				meta.IPAddress = &host
			}
		}
	}

	return meta
}

// requireAdmin verifies the authenticated caller has the "admin" role.
func RequireAdmin(ctx context.Context) (*crypto.Claims, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if claims.Role != "admin" {
		return nil, merr.Forbidden("PERMISSION_DENIED", "admin role required")
	}
	return claims, nil
}
