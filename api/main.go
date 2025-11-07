package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	HOST       = "127.0.0.1"
	PORT       = 8080
	ENV_SECRET = "JWT_AUTH_SECRET"
)

/* Middlewares */

func loggingMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

/* Payload and other types */

type httpMessage map[string]any

type LoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Tokens struct {
	AccessToken string `json:"access_token"`
}

/* Utility functions */

func generateJwtToken(username, secret string) (string, error) {
	jwtPayload := jwt.MapClaims{
		"username": username,
		"admin":    true,
	}

	generator := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtPayload)
	token, err := generator.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

/* Handlers */

func registerUser(w http.ResponseWriter, r *http.Request) {

}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var payload LoginPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[ERROR] login payload decode error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "invalid username or password",
			"type":  "BAD_REQUEST",
		})
		return
	}

	if payload.Username != "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "username is not found",
			"type":  "BAD_REQUEST",
		})
		return
	}
	if payload.Password != "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "password is incorrect",
			"type":  "BAD_REQUEST",
		})
		return
	}

	secretKey, ok := os.LookupEnv(ENV_SECRET)
	if !ok {
		log.Printf("[ERROR] %s environment variable is missing", ENV_SECRET)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "error in the server setup",
			"type":  "INTERNAL_ERROR",
		})
		return
	}

	jwt, err := generateJwtToken(payload.Username, secretKey)
	if err != nil {
		log.Printf("[ERROR] generating JWT token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "error in token generation",
			"type":  "INTERNAL_ERROR",
		})
		return
	}
	tokens := Tokens{
		AccessToken: jwt,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)
}

func getUserDetails(w http.ResponseWriter, r *http.Request) {

}

func logoutUser(w http.ResponseWriter, r *http.Request) {

}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/register", registerUser)
	mux.HandleFunc("POST /api/auth/login", loginUser)
	mux.HandleFunc("GET /api/auth/me", getUserDetails)
	mux.HandleFunc("POST /api/auth/logout", logoutUser)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", HOST, PORT),
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	log.Printf("Server started listening at %s:%d", HOST, PORT)
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("error while starting server: %s", err)
	}
}
