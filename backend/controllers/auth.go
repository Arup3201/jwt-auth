package controllers

import (
	"net/http"

	"example.com/jwt-auth/interfaces"
)

type authController struct {
}

func NewAuthController(authService interfaces.AuthService,
	emailService interfaces.EmailService) interfaces.AuthController {
	return &authController{}
}

func (ac *authController) Register(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) EmailVerificationStatus(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}
func (ac *authController) Login(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) PasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) ResetPassword(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) Logout(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}
func (ac *authController) Welcome(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (ac *authController) UserInfo(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}
