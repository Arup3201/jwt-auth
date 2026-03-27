package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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
	sessionDurationInSec int,
	resendApiKey string) *App {

	mux := http.NewServeMux()

	emailService := services.NewEmailService(db, resendApiKey)
	authService := services.NewAuthService(db,
		hashCost,
		rsaKey,
		time.Duration(sessionDurationInSec)*time.Second)
	authController := controllers.NewAuthController(authService, emailService)

	mux.HandleFunc("POST /api/register", authController.Register)
	mux.HandleFunc("GET /api/verify-email", authController.VerifyEmail)
	mux.HandleFunc("GET /api/email-verified", authController.EmailVerificationStatus)
	mux.HandleFunc("POST /api/login", authController.Login)
	mux.HandleFunc("POST /api/password-reset-link", authController.PasswordResetEmail)
	mux.HandleFunc("POST /api/reset-password", authController.ResetPassword)

	authMiddleware := middlewares.NewAuthMiddleware(authService, &rsaKey.PublicKey)
	mux.Handle("GET /api/message", authMiddleware.Next(http.HandlerFunc(authController.Welcome)))
	mux.Handle("GET /api/user-info", authMiddleware.Next(http.HandlerFunc(authController.UserInfo)))

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

	app := NewApp(db, 14, priv, 10, RESEND_API_KEY)

	err = app.Start("localhost", "8080")
	if err != nil {
		log.Fatalf("app failed to start with error: %s\n", err)
	}
}
