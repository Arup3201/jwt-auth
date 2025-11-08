package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	HOST                       = "127.0.0.1"
	PORT                       = 8080
	ENV_SECRET                 = "JWT_AUTH_SECRET"
	JWT_TOKEN_DURATION_SECONDS = 3600 // 1 hour
	ERROR_BAD_REQUEST          = "BAD_REQUEST"
	ERROR_UNAUTHORIZED         = "UNAUTHORIZED"
	ERROR_INTERNAL_ERROR       = "INTERNAL_ERROR"
)

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

type JwtClaims struct {
	Admin bool `json:"admin"`
	jwt.RegisteredClaims
}

func (j JwtClaims) Validate() error {
	sub, err := j.GetSubject()
	if err != nil {
		return fmt.Errorf("subject missing: %w", err)
	}

	for _, user := range Users {
		if user.Username == sub {
			if user.IsAdmin != j.Admin {
				return fmt.Errorf("incorrect admin value")
			}
			return nil
		}
	}

	return fmt.Errorf("invalid subject")
}

type Config struct {
	SecretKey string
}

/* Utility functions */

func generateJwtToken(username string, isAdmin bool, secret string) (string, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(JWT_TOKEN_DURATION_SECONDS) * 1000000000)
	payload := JwtClaims{
		Admin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    "JWTAuthenticator",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	generator := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	token, err := generator.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func verifyJwtToken(token string) (*User, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	jwtToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(configs.SecretKey), nil
	})

	if err != nil {
		return (*User)(nil), fmt.Errorf("jwt verfication error: %w", err)
	}

	claims := jwtToken.Claims.(jwt.MapClaims)
	return &User{
		Username: claims["sub"].(string),
		IsAdmin:  claims["admin"].(bool),
	}, nil
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

/* Middlewares */

func loggingMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authorizationMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/protected") {
			authorization := r.Header.Get("Authorization")
			token := strings.Fields(authorization)
			if token[0] != "Bearer" || len(token) != 2 {
				log.Printf("[ERROR] malformed authentication token")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(httpMessage{
					"error": "Malformed token received with request",
					"type":  ERROR_UNAUTHORIZED,
				})
				return
			}

			payload, err := verifyJwtToken(token[1])
			if err != nil {
				log.Printf("[ERROR] token verification failed: %s", err)
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(httpMessage{
					"error": "Token verification failed",
					"type":  ERROR_UNAUTHORIZED,
				})
				return
			}

			log.Printf("[INFO] JWT payload %v", payload)
		} else {
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
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
			"type":  ERROR_BAD_REQUEST,
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
					"type":  ERROR_BAD_REQUEST,
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
			"type":  ERROR_BAD_REQUEST,
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
			"type":  ERROR_INTERNAL_ERROR,
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
	mux.HandleFunc("POST /api/auth/logout", logoutUser)
	mux.HandleFunc("GET /api/protected/me", getUserDetails)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", HOST, PORT),
		Handler:      loggingMiddleware(authorizationMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	log.Printf("Server started listening at %s:%d", HOST, PORT)
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("error while starting server: %s", err)
	}
}
