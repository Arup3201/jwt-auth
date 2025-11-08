package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	TEST_URL_ROOT   = "http://localhost:8080"
	TEST_SECRET_KEY = "a-string-secret-at-least-256-bits-long"
)

func TestMain(m *testing.M) {
	configs.SecretKey = TEST_SECRET_KEY

	code := m.Run()

	os.Exit(code)
}

func TestLogin(t *testing.T) {
	t.Run("returns access token when valid user logs in", func(t *testing.T) {
		// prepare
		username := "admin01"
		password := "topsecret01"
		payload, _ := json.Marshal(map[string]any{
			"username": username,
			"password": password,
		})
		resourcePath := "/api/auth/login"
		req := httptest.NewRequest("POST", resourcePath, bytes.NewReader(payload))
		rec := httptest.NewRecorder()

		// act
		loginUser(rec, req)
		response := rec.Result()

		// assert
		assert.Equal(t, 200, response.StatusCode)

		var tokens Tokens
		if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
			t.Fail()
			t.Logf("login assert failed: json encoding failed: %s", err)
			return
		}

		expectedAccessToken, err := generateJwtToken(username, true, TEST_SECRET_KEY)
		if err != nil {
			t.Fail()
			t.Logf("login assert failed: access token generation failed: %s", err)
			return
		}
		assert.Equal(t, expectedAccessToken, tokens.AccessToken)
	})
	t.Run("login fails for invalid username", func(t *testing.T) {
		// prepare
		username := "randomUser"
		password := "randomSecret"
		payload, _ := json.Marshal(map[string]any{
			"username": username,
			"password": password,
		})
		resourcePath := "/api/auth/login"
		req := httptest.NewRequest("POST", resourcePath, bytes.NewReader(payload))
		rec := httptest.NewRecorder()

		// act
		loginUser(rec, req)
		response := rec.Result()

		// assert
		assert.Equal(t, 400, response.StatusCode)
	})
	t.Run("login fails for correct username but wrong password", func(t *testing.T) {
		// prepare
		username := "admin01"
		password := "topsecret02"
		payload, _ := json.Marshal(map[string]any{
			"username": username,
			"password": password,
		})
		resourcePath := "/api/auth/login"
		req := httptest.NewRequest("POST", resourcePath, bytes.NewReader(payload))
		rec := httptest.NewRecorder()

		// act
		loginUser(rec, req)
		response := rec.Result()

		// assert
		assert.Equal(t, 400, response.StatusCode)
	})
}

func TestAuthorization(t *testing.T) {
	t.Run("logged in user can access user details", func(t *testing.T) {
		// prepare
		username := "admin01"
		password := "topsecret01"
		payload, _ := json.Marshal(map[string]any{
			"username": username,
			"password": password,
		})
		resourcePath := "/api/auth/login"
		req := httptest.NewRequest("POST", resourcePath, bytes.NewReader(payload))
		rec := httptest.NewRecorder()
		loginUser(rec, req)
		response := rec.Result()
		var tokens Tokens
		if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
			t.Fail()
			t.Logf("login failed: JSON decode error: %s", err)
			return
		}
		resourcePath = "/api/protected/me"
		req = httptest.NewRequest("GET", resourcePath, nil)
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))
		rec = httptest.NewRecorder()

		// act
		handler := http.HandlerFunc(getUserDetails)
		authorizationMiddleware(handler).ServeHTTP(rec, req)

		// assert
		assert.Equal(t, 200, response.StatusCode)
	})
	t.Run("user can't access user details without access token", func(t *testing.T) {})
	t.Run("access token verification failed with signature stripping", func(t *testing.T) {})
}
