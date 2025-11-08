package main

import (
	"bytes"
	"encoding/json"
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

func TestGenerateJwt(t *testing.T) {
	// prepare
	username := "admin01"

	// act
	token, err := generateJwtToken(username, true, TEST_SECRET_KEY)

	// assert
	if err != nil {
		t.Fail()
		t.Logf("generate JWT token failed: %s", err)
		return
	}

	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidXNlcm5hbWUiOiJhZG1pbjAxIn0.pvzh8DWcI9jxwWnFRhTH2RCGslSRpDFsMo2nE7auHls"
	assert.Equal(t, expectedToken, token)
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
}
