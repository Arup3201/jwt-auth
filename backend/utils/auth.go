package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"example.com/go-jwt-auth/models"
)

const (
	USER_KEY = "USER"
)

// NewContext returns a new Context that carries value u.
func NewContext(ctx context.Context, u models.User) context.Context {
	return context.WithValue(ctx, USER_KEY, u)
}

// FromContext returns the User value stored in ctx, if any.
func FromContext(ctx context.Context) (models.User, bool) {
	u, ok := ctx.Value(USER_KEY).(models.User)
	return u, ok
}

func GenerateHashedToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	return token, nil
}

func HashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	tokenSHA := hex.EncodeToString(h.Sum(nil))

	return tokenSHA
}
