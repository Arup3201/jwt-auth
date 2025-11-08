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

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"-"`
}

type Config struct {
	SecretKey string
}

/* Global variables */

var configs = Config{}

var Users = []User{
	{
		Username: "admin01",
		Password: "topsecret01",
		IsAdmin:  true,
	},
	{
		Username: "admin01",
		Password: "topsecret01",
		IsAdmin:  true,
	},
	{
		Username: "user01",
		Password: "secret01",
		IsAdmin:  false,
	},
	{
		Username: "user02",
		Password: "secret02",
		IsAdmin:  false,
	},
}

/* Utility functions */

func generateJwtToken(username string, isAdmin bool, secret string) (string, error) {
	jwtPayload := jwt.MapClaims{
		"username": username,
		"admin":    isAdmin,
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
			"error": "Invalid username or password",
			"type":  "BAD_REQUEST",
		})
		return
	}

	var record User
	for _, user := range Users {
		if user.Username == payload.Username {
			if payload.Password != user.Password {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(httpMessage{
					"error": "Password is not correct",
					"type":  "BAD_REQUEST",
				})
				return
			} else if payload.Password == user.Password {
				record = user
			}
		}
	}

	if record.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "Username is not registered",
			"type":  "BAD_REQUEST",
		})
		return
	}

	secretKey := configs.SecretKey
	jwt, err := generateJwtToken(record.Username, record.IsAdmin, secretKey)
	if err != nil {
		log.Printf("[ERROR] generating JWT token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "Error while generating login token",
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
	secretKey, ok := os.LookupEnv(ENV_SECRET)
	if !ok {
		log.Fatalf("[ERROR] %s environment variable is missing", ENV_SECRET)
	}
	configs.SecretKey = secretKey

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
