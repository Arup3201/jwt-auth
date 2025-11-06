package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	HOST = "127.0.0.1"
	PORT = 8080
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

/* Handlers */

func loginUser(w http.ResponseWriter, r *http.Request) {
	var payload LoginPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[ERROR] login payload decode error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(httpMessage{
			"error": "invalid payload format",
			"type":  "BAD_REQUEST",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(httpMessage{
		"message": "implementing login",
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginUser)

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
