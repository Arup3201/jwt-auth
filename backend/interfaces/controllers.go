package interfaces

import "net/http"

type AuthController interface {
	Register(w http.ResponseWriter, r *http.Request)
	VerifyEmail(w http.ResponseWriter, r *http.Request)
	EmailVerificationStatus(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	PasswordResetEmail(w http.ResponseWriter, r *http.Request)
	ResetPassword(w http.ResponseWriter, r *http.Request)
	UserInfo(w http.ResponseWriter, r *http.Request)
	Welcome(w http.ResponseWriter, r *http.Request)
}
