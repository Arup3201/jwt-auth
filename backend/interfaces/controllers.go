package interfaces

import "net/http"

type AuthController interface {
	Register(w http.ResponseWriter, r *http.Request)
	VerifyEmail(w http.ResponseWriter, r *http.Request)
	EmailVerificationStatus(w http.ResponseWriter, r *http.Request)
}
