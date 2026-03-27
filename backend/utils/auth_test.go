package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewClaims(t *testing.T) {
	var iss, sub, uId string
	var exp time.Time
	iss = "https://auth.go.com"
	sub = "sample_sub"
	uId = "123"
	exp = time.Now().Add(10 * time.Second)

	claims := NewClaims(iss, sub, uId, exp)

	assert.NotNil(t, claims)
	assert.Equal(t, claims.Issuer, iss)
	assert.Equal(t, claims.Subject, sub)
	assert.Equal(t, claims.UserId, uId)
	assert.Equal(t, claims.Expiry, exp)
}

func TestJWTFromClaims(t *testing.T) {
	var iss, sub, uId string
	var exp time.Time
	iss = "https://auth.go.com"
	sub = "sample_sub"
	uId = "123"
	exp = time.Now().Add(10 * time.Second)
	claims := NewClaims(iss, sub, uId, exp)

	jwt, err := JWTFromClaims(claims, JWT_ALG_HMAC)

	assert.NoError(t, err)
	assert.Equal(t, jwtv5.SigningMethodHS256, jwt.Alg)
	assert.Equal(t, "https://auth.go.com", jwt.Claims.Issuer)
}

func TestJWTSign_HMAC(t *testing.T) {
	var iss, sub, uId string
	var exp time.Time
	iss = "https://auth.go.com"
	sub = "sample_sub"
	uId = "123"
	exp = time.Now().Add(10 * time.Second)
	claims := NewClaims(iss, sub, uId, exp)
	jwt, _ := JWTFromClaims(claims, JWT_ALG_HMAC)
	secret := "secret"

	tokenStr, err := jwt.Sign([]byte(secret))

	assert.NoError(t, err)

	token, err := jwtv5.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwtv5.Token) (any, error) {
		return []byte(secret), nil
	})
	assert.NoError(t, err)
	if claims, ok := token.Claims.(*CustomClaims); ok {
		assert.Equal(t, uId, claims.UserId)
		assert.Equal(t, sub, claims.Subject)
		assert.Equal(t, iss, claims.Issuer)
	}
}

func TestJWTSign_RSA(t *testing.T) {
	var iss, sub, uId string
	var exp time.Time
	iss = "https://auth.go.com"
	sub = "sample_sub"
	uId = "123"
	exp = time.Now().Add(10 * time.Second)
	claims := NewClaims(iss, sub, uId, exp)
	jwt, _ := JWTFromClaims(claims, JWT_ALG_RSA)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	tokenStr, err := jwt.Sign(priv)

	assert.NoError(t, err)

	token, err := jwtv5.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwtv5.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	assert.NoError(t, err)
	if claims, ok := token.Claims.(*CustomClaims); ok {
		assert.Equal(t, uId, claims.UserId)
		assert.Equal(t, sub, claims.Subject)
		assert.Equal(t, iss, claims.Issuer)
	}
}

func TestClaimsFromToken(t *testing.T) {
	var iss, sub, uId string
	var exp time.Time
	iss = "https://auth.go.com"
	sub = "sample_sub"
	uId = "123"
	exp = time.Now().Add(10 * time.Second)
	key := "secret"
	claims := CustomClaims{
		UserId: uId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(exp),
			IssuedAt:  jwtv5.NewNumericDate(time.Now()),
			NotBefore: jwtv5.NewNumericDate(time.Now()),
			Issuer:    iss,
			Subject:   sub,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(key))

	jwtClaims, err := ClaimsFromToken(signed, []byte(key))

	assert.NoError(t, err)
	assert.Equal(t, iss, jwtClaims.Issuer)
	assert.Equal(t, sub, jwtClaims.Subject)
	assert.Equal(t, uId, jwtClaims.UserId)
}
