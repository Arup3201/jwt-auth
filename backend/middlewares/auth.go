package middlewares

import (
	"crypto/rsa"
	"log"
	"net/http"
	"strings"

	"example.com/go-jwt-auth/interfaces"
	"example.com/go-jwt-auth/utils"
)

// Middleware to block unauthorized requests. It extracts the user session
// from request cookie and checks it's validity. next is the handler that
// needs authorization.
type authMiddleware struct {
	publicKey   *rsa.PublicKey
	authService interfaces.AuthService
}

func NewAuthMiddleware(authService interfaces.AuthService,
	publicKey *rsa.PublicKey) *authMiddleware {
	return &authMiddleware{
		authService: authService,
		publicKey:   publicKey,
	}
}

func (m *authMiddleware) Next(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if strings.Trim(bearer, " ") == "" {
			log.Printf("[ERROR] missing bearer token\n")

			http.Error(w, "Authorization token missing", http.StatusUnauthorized)
			return
		}
		bearerToken := strings.Fields(bearer)
		if bearerToken[0] != "Bearer" {
			log.Printf("[ERROR] not a bearer token\n")

			http.Error(w, "Malformed authorization token", http.StatusUnauthorized)
			return
		}

		claims, err := utils.ClaimsFromToken(bearerToken[1], m.publicKey)
		if err != nil {
			log.Printf("[ERROR] claims from token: %s\n", err)

			http.Error(w, "Failed to get claims from token", http.StatusUnauthorized)
			return
		}

		user, err := m.authService.GetUser(r.Context(), claims.UserId)
		if err != nil {
			log.Printf("[ERROR] get user: %s\n", err)

			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		reqWithCtx := r.WithContext(utils.NewContext(r.Context(), user))

		next.ServeHTTP(w, reqWithCtx)
	})
}
