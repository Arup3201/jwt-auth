package main

import (
	"context"
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
	UI_HOST                    = "http://localhost:5173"
	ENV_SECRET                 = "JWT_AUTH_SECRET"
	JWT_TOKEN_DURATION_SECONDS = 3600 // 1 hour
	ERROR_BAD_REQUEST          = "BAD_REQUEST"
	ERROR_UNAUTHORIZED         = "UNAUTHORIZED"
	ERROR_INTERNAL_ERROR       = "INTERNAL_ERROR"
)

/* Payload and other types */

type httpMessage map[string]any

type Config struct {
	SecretKey string
}

type ContextKey string

type Endpoint struct {
	Method  string
	URLPath string
	Handler http.HandlerFunc
}

type LoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Tokens struct {
	AccessToken string `json:"access_token"`
}

type Address struct {
	Street   string `json:"street"`
	State    string `json:"state"`
	City     string `json:"city"`
	PostCode string `json:"post_code"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"-"`
	IsAdmin  bool   `json:"-"`
	FullName string `json:"full_name"`
	Address
	Company     string `json:"company"`
	Designation string `json:"designation"`
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
		FullName: "Rakesh Chopra",
		Address: Address{
			Street:   "Alkapuri, R.C. Dutt Road",
			City:     "Vadodara",
			State:    "Gujarat",
			PostCode: "390005",
		},
		Company:     "TCS",
		Designation: "IT Support Engineer",
	},
	{
		Username: "admin02",
		Password: "topsecret01",
		IsAdmin:  true,
		FullName: "Sunil Upadhay",
		Address: Address{
			Street:   "Cyber City, Building 5, DLF Cyber Hub, Sector 24",
			City:     "Gurgaon",
			State:    "Haryana",
			PostCode: "122002",
		},
		Company:     "Wipro",
		Designation: "Network Troubleshooter",
	},
	{
		Username: "user01",
		Password: "secret01",
		IsAdmin:  false,
		FullName: "Sunita Shetty",
		Address: Address{
			Street:   "Tonk Road, Durgapura, Near Airport",
			City:     "Jaipur",
			State:    "Rajasthan",
			PostCode: "302015",
		},
		Company:     "TCS",
		Designation: "IT Support Intern",
	},
	{
		Username: "user02",
		Password: "secret02",
		IsAdmin:  false,
		FullName: "Purbi Devi",
		Address: Address{
			Street:   "Gariahat Road, 46, Parveen Apartments, Zeeshan Chowk",
			City:     "Kolkata",
			State:    "West Bengal",
			PostCode: "700029",
		},
		Company:     "TCS",
		Designation: "IT Support Intern",
	},
}

var authPayloadKey ContextKey = "authPayload"

var endpoints = []Endpoint{
	{
		Method:  "POST",
		URLPath: "/api/auth/register",
		Handler: registerUser,
	},
	{
		Method:  "POST",
		URLPath: "/api/auth/login",
		Handler: loginUser,
	},
	{
		Method:  "POST",
		URLPath: "/api/auth/logout",
		Handler: logoutUser,
	},
	{
		Method:  "GET",
		URLPath: "/api/protected/me",
		Handler: getUserDetails,
	},
}

/* Middlewares */

func LoggingMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func AuthorizationMiddleware(next http.Handler) http.Handler {
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

			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(60*time.Second))
			defer cancel()

			ctx = context.WithValue(ctx, authPayloadKey, payload)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			for _, e := range endpoints {
				if strings.Contains(r.URL.Path, e.URLPath) {
					w.Header().Set("Access-Control-Allow-Origin", UI_HOST)
					w.Header().Set("Access-Control-Allow-Methods", e.Method)
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.WriteHeader(http.StatusOK)
					return
				}
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

		next.ServeHTTP(w, r)
	})
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
	ctx := r.Context()
	payload := ctx.Value(authPayloadKey)
	userPayload := *payload.(*User)

	var userDetails User
	for _, u := range Users {
		if u.Username == userPayload.Username {
			userDetails = u
		}
	}

	json.NewEncoder(w).Encode(userDetails)
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
	for _, e := range endpoints {
		mux.HandleFunc(fmt.Sprintf("%s %s", e.Method, e.URLPath), e.Handler)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", HOST, PORT),
		Handler:      LoggingMiddleware(CORSMiddleware(AuthorizationMiddleware(mux))),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	log.Printf("Server started listening at %s:%d", HOST, PORT)
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("error while starting server: %s", err)
	}
}
