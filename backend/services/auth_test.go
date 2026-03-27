package services

import (
	"context"
	"strconv"
	"testing"
	"time"

	"example.com/go-jwt-auth/models"
	"example.com/go-jwt-auth/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	TEST_HASH_COST        = 14
	TEST_SESSION_DURATION = 1 * time.Minute
)

func TestAuthService_Login(t *testing.T) {
	var err error
	var db *gorm.DB

	db, err = gorm.Open(sqlite.Open(DB_PATH), &gorm.Config{
		TranslateError: true,
		Logger:         logger.Default.LogMode(logger.Silent),
	})
	assert.NoError(t, err)

	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("vaew2Iehexi"), TEST_HASH_COST)
	testUser := models.User{
		Email:         "JordanNRobinson@jourrapide.com",
		FullName:      "Jordan N. Robinson",
		Password:      string(hash),
		EmailVerified: true,
	}
	privateKey := "private_scret_key"

	err = gorm.G[models.User](db).Create(ctx, &testUser)
	assert.NoError(t, err)

	authService := NewAuthService(db, TEST_HASH_COST, privateKey, TEST_SESSION_DURATION)

	t.Run("should login with not empty token", func(t *testing.T) {
		tokenObj, err := authService.Login(ctx, testUser.Email, "vaew2Iehexi")
		assert.NoError(t, err)
		assert.NotNil(t, tokenObj)
	})
	t.Run("should give token with user id", func(t *testing.T) {
		tokenObj, _ := authService.Login(ctx, testUser.Email, "vaew2Iehexi")

		token, err := jwt.ParseWithClaims(tokenObj.Value, &utils.CustomClaims{}, func(t *jwt.Token) (any, error) {
			return []byte(privateKey), nil
		})
		if !assert.NoError(t, err) {
			return
		}
		claims, ok := token.Claims.(*utils.CustomClaims)
		if !assert.Equal(t, true, ok) {
			return
		}
		assert.Equal(t, strconv.Itoa(int(testUser.ID)), claims.UserId)
	})
}
