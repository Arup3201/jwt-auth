package interfaces

import "net/http"

type AuthMiddleware interface {
	Next(next http.Handler) http.Handler
}
