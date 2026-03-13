package middlewares

import (
	"net/http"

	"example.com/jwt-auth/interfaces"
)

type authMiddleware struct{}

func NewAuthMiddleware(authService interfaces.AuthService) interfaces.AuthMiddleware {
	return &authMiddleware{}
}

func (am *authMiddleware) Next(next http.Handler) http.Handler {
	panic("TODO")
}
