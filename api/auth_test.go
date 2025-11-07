package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	TEST_URL_ROOT = "http://localhost:8080"
)

func TestGenerateJwt(t *testing.T) {
	// prepare
	username := "admin"

	// act
	token, err := generateJwtToken(username, "a-string-secret-at-least-256-bits-long")

	// assert
	if err != nil {
		t.Fail()
		t.Logf("generate JWT token failed: %s", err)
		return
	}

	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidXNlcm5hbWUiOiJhZG1pbiJ9.rP2FCArxwPaFsyvVJ5v9WHuI_U2Es1W6EYBnlCxM9LQ"
	assert.Equal(t, expectedToken, token)
}

func TestLogin(t *testing.T) {
	t.Run("returns access token when valid user logs in", func(t *testing.T) {
		// prepare
		username := "admin"
		password := "admin"
		payload, _ := json.Marshal(map[string]any{
			"username": username,
			"password": password,
		})
		resourcePath := "/api/auth/login"
		contentType := "application/json"

		// act
		response, err := http.Post(TEST_URL_ROOT+resourcePath, contentType, bytes.NewReader(payload))

		// assert
		if err != nil {
			t.Fail()
			t.Logf("login assert failed: post request failed with payload username=%s, password=%s", username, password)
			return
		}
		assert.Equal(t, 200, response.StatusCode)

		var tokens Tokens
		if err = json.NewDecoder(response.Body).Decode(&tokens); err != nil {
			t.Fail()
			t.Logf("login assert failed: json encoding failed: %s", err)
			return
		}

		expectedAccessToken, err := generateJwtToken(username, "a-string-secret-at-least-256-bits-long")
		if err != nil {
			t.Fail()
			t.Logf("login assert failed: access token generation failed: %s", err)
			return
		}
		assert.Equal(t, expectedAccessToken, tokens.AccessToken)
	})
}
