package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"example.com/go-jwt-auth/constants"
	"example.com/go-jwt-auth/interfaces"
	"example.com/go-jwt-auth/utils"
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

func (ac *authController) Login(w http.ResponseWriter, r *http.Request) {

	type loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var data loginData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts email and password",
			http.StatusBadRequest)
		return
	}

	token, err := ac.authService.Login(r.Context(), data.Email, data.Password)
	if err != nil {
		log.Printf("[ERROR] auth service login: %s\n", err)

		http.Error(w,
			"Encountered error while logging in. Please try again with correct credentials.",
			http.StatusInternalServerError)
		return
	}

	accessTokenCookie := &http.Cookie{
		Name:     constants.ACCESS_TOKEN_NAME,
		Value:    token.AccessToken,
		Expires:  token.AccessTokenExpiresAt,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, accessTokenCookie)

	refreshTokenCookie := &http.Cookie{
		Name:     constants.REFRESH_TOKEN_NAME,
		Value:    token.RefreshToken,
		Expires:  token.RefreshTokenExpiresAt,
		Path:     constants.API_PATH + "/auth/refresh",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, refreshTokenCookie)

	responseBody := map[string]any{
		"message": "Logged in successfully",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (ac *authController) PasswordResetEmail(w http.ResponseWriter, r *http.Request) {

	type forgotPasswordReq struct {
		Email string `json:"email"`
	}

	var data forgotPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts only email",
			http.StatusBadRequest)
		return
	}

	err := ac.emailService.SendPasswordResetEmail(r.Context(), data.Email)
	if err != nil {
		log.Printf("[ERROR] auth service login: %s\n", err)

		http.Error(w,
			"Encountered error while sending password reset email. Please try again with valid email.",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"message": "Reset password email has been sent to the email address",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (ac *authController) ResetPassword(w http.ResponseWriter, r *http.Request) {

	type resetPasswordReq struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	var data resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts token and password",
			http.StatusBadRequest)
		return
	}

	err := ac.authService.ResetPassword(r.Context(), data.Token, data.Password)
	if err != nil {
		log.Printf("[ERROR] auth service reset password: %s\n", err)

		http.Error(w,
			"Encountered error while resetting password.",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"message": "Password reset successful",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (ac *authController) UserInfo(w http.ResponseWriter, r *http.Request) {

	user, ok := utils.FromContext(r.Context())
	if !ok {
		http.Error(w, "Error extracting user data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"id":         user.ID,
		"full_name":  user.FullName,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	})
}

func (ac *authController) Welcome(w http.ResponseWriter, r *http.Request) {

	_, ok := utils.FromContext(r.Context())
	if !ok {
		http.Error(w, "Error extracting user data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome to the site",
	})
}
