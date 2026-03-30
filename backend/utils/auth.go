package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"example.com/go-jwt-auth/constants"
	"example.com/go-jwt-auth/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTClaims struct {
	Jti       string    `json:"jti"`
	Issuer    string    `json:"iss"`
	UserId    string    `json:"user_id"`
	Subject   string    `json:"sub"`
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
	Expiry    time.Time `json:"exp"`
}

func NewClaims(iss, sub, userId string, exp time.Time) *JWTClaims {
	now := time.Now().UTC()
	jti := uuid.NewString()

	return &JWTClaims{
		Jti:       jti,
		Issuer:    iss,
		Subject:   sub,
		UserId:    userId,
		IssuedAt:  now,
		NotBefore: now,
		Expiry:    exp,
	}
}

func ClaimsFromToken(tokenString string, key any) (*JWTClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		return key, nil
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
	case constants.JWT_ALG_ECDSA:
		obj.Alg = jwt.SigningMethodES256
	case constants.JWT_ALG_ED25519:
		obj.Alg = jwt.SigningMethodEdDSA
	case constants.JWT_ALG_HMAC:
		obj.Alg = jwt.SigningMethodHS256
	case constants.JWT_ALG_RSA:
		obj.Alg = jwt.SigningMethodRS256
	default:
		return nil, errors.New("invalid jwt algorithm")
	}

	return &obj, nil
}

func (t *JWT) Sign(key any) (string, error) {

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
	token := jwt.NewWithClaims(t.Alg, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("jwt sign: %w", err)
	}

	return signed, nil
}

func GetToken(name string, cookies []*http.Cookie) (string, error) {
	tInd := slices.IndexFunc(cookies, func(c *http.Cookie) bool {
		return c.Name == name
	})
	if tInd == -1 {
		return "", fmt.Errorf("token cookie not found")
	}

	token := cookies[tInd].Value
	if token == "" {
		return "", fmt.Errorf("token value is empty")
	}

	return token, nil
}

// NewContext returns a new Context that carries value u.
func NewContext(ctx context.Context, u models.User) context.Context {
	return context.WithValue(ctx, constants.USER_KEY, u)
}

// FromContext returns the User value stored in ctx, if any.
func FromContext(ctx context.Context) (models.User, bool) {
	u, ok := ctx.Value(constants.USER_KEY).(models.User)
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
