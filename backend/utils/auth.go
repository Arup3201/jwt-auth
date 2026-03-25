package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"example.com/go-jwt-auth/models"
	"github.com/golang-jwt/jwt/v5"
)

const (
	USER_KEY = "USER"

	JWT_ALG_ECDSA   = "ECDSA"
	JWT_ALG_ED25519 = "ED25519"
	JWT_ALG_HMAC    = "HMAC"
	JWT_ALG_RSA     = "RSA"
)

type JWTClaims struct {
	Issuer    string    `json:"iss"`
	UserId    string    `json:"user_id"`
	Subject   string    `json:"sub"`
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
	Expiry    time.Time `json:"exp"`
}

func NewClaims(iss, sub, userId string, exp time.Time) *JWTClaims {
	now := time.Now().UTC()

	return &JWTClaims{
		Issuer:    iss,
		Subject:   sub,
		UserId:    userId,
		IssuedAt:  now,
		NotBefore: now,
		Expiry:    exp,
	}
}

func ClaimsFromToken(tokenString, key string) (*JWTClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt parse with claims: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("token claims is not of type CustomClaims")
	}

	jwtClaims := JWTClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		UserId:    claims.UserId,
		IssuedAt:  claims.IssuedAt.Time,
		NotBefore: claims.NotBefore.Time,
		Expiry:    claims.ExpiresAt.Time,
	}

	return &jwtClaims, nil
}

type CustomClaims struct {
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

type JWT struct {
	Claims *JWTClaims
	Alg    jwt.SigningMethod
}

func JWTFromClaims(claims *JWTClaims,
	alg string) (*JWT, error) {

	obj := JWT{
		Claims: claims,
	}

	switch alg {
	case JWT_ALG_ECDSA:
		obj.Alg = jwt.SigningMethodES256
	case JWT_ALG_ED25519:
		obj.Alg = jwt.SigningMethodEdDSA
	case JWT_ALG_HMAC:
		obj.Alg = jwt.SigningMethodHS256
	case JWT_ALG_RSA:
		obj.Alg = jwt.SigningMethodRS256
	default:
		return nil, errors.New("invalid jwt algorithm")
	}

	return &obj, nil
}

func (t *JWT) Sign(key string) (string, error) {

	claims := CustomClaims{
		UserId: t.Claims.UserId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(t.Claims.Expiry),
			IssuedAt:  jwt.NewNumericDate(t.Claims.IssuedAt),
			NotBefore: jwt.NewNumericDate(t.Claims.NotBefore),
			Issuer:    t.Claims.Issuer,
			Subject:   t.Claims.Subject,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("jwt sign: %w", err)
	}

	return signed, nil
}

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
