package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/go-jwt-auth/constants"
	"example.com/go-jwt-auth/controllers"
	"example.com/go-jwt-auth/middlewares"
	"example.com/go-jwt-auth/models"
	"example.com/go-jwt-auth/services"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type App struct {
	mux *http.ServeMux
}

func NewApp(db *gorm.DB,
	hashCost int,
	rsaKey *rsa.PrivateKey,
	sessionDurationInMin int,
	refreshDurationInHours int,
	resendApiKey string) *App {

	mux := http.NewServeMux()

	emailService := services.NewEmailService(db, resendApiKey)
	authService := services.NewAuthService(db,
		hashCost,
		rsaKey,
		time.Duration(sessionDurationInMin)*time.Minute,
		time.Duration(refreshDurationInHours)*time.Hour)
	authController := controllers.NewAuthController(authService, emailService)

	mux.HandleFunc(fmt.Sprintf("POST /%s/register", constants.API_PATH), authController.Register)
	mux.HandleFunc(fmt.Sprintf("GET /%s/verify-email", constants.API_PATH), authController.VerifyEmail)
	mux.HandleFunc(fmt.Sprintf("GET /%s/email-verified", constants.API_PATH), authController.EmailVerificationStatus)
	mux.HandleFunc(fmt.Sprintf("POST /%s/login", constants.API_PATH), authController.Login)
	mux.HandleFunc(fmt.Sprintf("POST /%s/password-reset-link", constants.API_PATH), authController.PasswordResetEmail)
	mux.HandleFunc(fmt.Sprintf("POST /%s/reset-password", constants.API_PATH), authController.ResetPassword)

	authMiddleware := middlewares.NewAuthMiddleware(authService, &rsaKey.PublicKey)
	mux.Handle(fmt.Sprintf("GET /%s/message", constants.API_PATH), authMiddleware.Next(http.HandlerFunc(authController.Welcome)))
	mux.Handle(fmt.Sprintf("GET /%s/user-info", constants.API_PATH), authMiddleware.Next(http.HandlerFunc(authController.UserInfo)))

	return &App{
		mux: mux,
	}
}

func (a *App) Start(host, port string) error {
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", host, port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      CorsMiddleware(a.mux),
	}

	log.Printf("[INFO] Server starting at %s:%s\n", host, port)

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("server listen and serve: %w", err)
	}

	return nil
}

func main() {
	var err error
	var db *gorm.DB

	db, err = gorm.Open(sqlite.Open("db/development.db"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		log.Fatalf("gorm open failed with error: %s\n", err)
	}

	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.RefreshToken{})
	db.AutoMigrate(&models.EmailVerification{})
	db.AutoMigrate(&models.PasswordResetToken{})

	RESEND_API_KEY := os.Getenv("RESEND_API_KEY")
	if RESEND_API_KEY == "" {
		log.Fatal("Missing RESEND_API_KEY\n")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa generate key: %s\n", err)
	}

	app := NewApp(db,
		14, // Password hash cost
		priv,
		15,    // Access Token Duration
		10*24, // Refresh Token Duration
		RESEND_API_KEY,
	)

	err = app.Start("localhost", "8080")
	if err != nil {
		log.Fatalf("app failed to start with error: %s\n", err)
	}
}
