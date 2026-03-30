package middlewares

import (
	"crypto/rsa"
	"log"
	"net/http"

	"example.com/go-jwt-auth/constants"
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
		token, err := utils.GetToken(constants.ACCESS_TOKEN_NAME, r.Cookies())
		if err != nil {
			log.Printf("[ERROR] get token: %s\n", err)

			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := utils.ClaimsFromToken(token, m.publicKey)
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
