package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"example.com/go-jwt-auth/interfaces"
)

type authController struct {
	authService  interfaces.AuthService
	emailService interfaces.EmailService
}

func NewAuthController(authService interfaces.AuthService,
	emailService interfaces.EmailService) interfaces.AuthController {
	return &authController{
		authService:  authService,
		emailService: emailService,
	}
}

func (ac *authController) Register(w http.ResponseWriter, r *http.Request) {

	type registerData struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Password string `json:"password"`
	}

	var data registerData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts email, full_name and password",
			http.StatusBadRequest)
		return
	}

	id, err := ac.authService.Register(r.Context(), data.Email, data.FullName, data.Password)
	if err != nil {
		log.Printf("[ERROR] authentication service register: %s\n", err)

		http.Error(w,
			"Registration failed. Make sure email is valid, full name and password is not empty",
			http.StatusInternalServerError)
		return
	}

	err = ac.emailService.SendVerificationEmail(r.Context(),
		strconv.Itoa(int(id)),
		data.Email,
		data.FullName)
	if err != nil {
		log.Printf("[ERROR] email service send verification email: %s\n", err)

		http.Error(w,
			"Failed to send verification email to the email",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"id":      id,
		"message": "User has registered successfully",
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseBody)
}

func (ac *authController) VerifyEmail(w http.ResponseWriter, r *http.Request) {

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w,
			"Empty token not allowed",
			http.StatusBadRequest)
		return
	}

	err := ac.emailService.VerifyEmail(r.Context(), token)
	if err != nil {
		log.Printf("[ERROR] verify email: %s\n", err)

		http.Error(w,
			"Failed to verify email",
			http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "http://localhost:5173", http.StatusSeeOther)
}

func (ac *authController) EmailVerificationStatus(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w,
			"Empty email not allowed",
			http.StatusBadRequest)
		return
	}

	isVerified, err := ac.emailService.GetEmailVerificationStatus(r.Context(), email)
	if err != nil {
		log.Printf("[ERROR] get email verification status: %s\n", err)

		http.Error(w,
			"Failed to check email verification status",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"is_verified": isVerified,
	}
	json.NewEncoder(w).Encode(responseBody)
}
