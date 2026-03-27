package services

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.com/go-jwt-auth/interfaces"
	"example.com/go-jwt-auth/models"
	"example.com/go-jwt-auth/utils"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const ISSUER = "https://auth.jwt.com"

type authService struct {
	db              *gorm.DB
	hashCost        int
	sessionDuration time.Duration
	privateKey      string
	emailChecker    *regexp.Regexp
}

func NewAuthService(db *gorm.DB,
	hCost int,
	privateKey string,
	sessionDuration time.Duration) interfaces.AuthService {

	var emailRegex, _ = regexp.Compile(
		`^[a-zA-Z0-9]+([._-][0-9a-zA-Z]+)*@[a-zA-Z0-9]+([.-][0-9a-zA-Z]+)*\.[a-zA-Z]{2,}$`,
	)

	return &authService{
		db:              db,
		hashCost:        hCost,
		sessionDuration: sessionDuration,
		emailChecker:    emailRegex,
		privateKey:      privateKey,
	}
}

func (as *authService) Register(ctx context.Context,
	email, fullName, password string) (uint, error) {
	var err error

	if match := as.emailChecker.Find([]byte(email)); match == nil {
		return 0, fmt.Errorf("email address is invalid")
	}

	if strings.Trim(fullName, " ") == "" {
		return 0, fmt.Errorf("full name cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), as.hashCost)
	if err != nil {
		return 0, fmt.Errorf("bcrypt generate from password: %w", err)
	}

	user := models.User{
		Email:         email,
		FullName:      fullName,
		Password:      string(hashedPassword),
		EmailVerified: false,
	}

	err = gorm.G[models.User](as.db).Create(ctx, &user)
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}

	return user.ID, nil
}

func (as *authService) Login(ctx context.Context,
	email, password string) (*interfaces.Token, error) {

	user, err := gorm.G[models.User](as.db).Where("email = ?", email).First(ctx)
	if err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			return nil, fmt.Errorf("email not found")
		default:
			return nil, fmt.Errorf("sql where first: %w", err)
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("password mismatch")
	}

	if !user.EmailVerified {
		return nil, fmt.Errorf("email verification pending")
	}

	var issuer, subject, userId string
	var expiry time.Time

	issuer = ISSUER
	userId = strconv.Itoa(int(user.ID))
	subject = userId
	expiry = time.Now().Add(as.sessionDuration)
	claims := utils.NewClaims(issuer, subject, userId, expiry)

	jwt, err := utils.JWTFromClaims(claims, utils.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("utils jwt from claims: %w", err)
	}

	token, err := jwt.Sign(as.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	return &interfaces.Token{
		Value:     token,
		ExpiresAt: expiry,
	}, nil
}

func (as *authService) ResetPassword(ctx context.Context, token, password string) error {

	tokenSHA := utils.HashToken(token)
	now := time.Now().UTC()

	err := as.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rt, err := gorm.G[models.PasswordResetToken](tx).
			Where("hashed_token = ? AND used_at IS NULL AND expires_at >= ?",
				tokenSHA, now).
			First(ctx)
		if err != nil {
			return fmt.Errorf("find password reset token with token hash: %w", err)
		}

		rt.UsedAt = &now
		if err := tx.Save(&rt).Error; err != nil {
			return fmt.Errorf("mark password reset token as used: %w", err)
		}

		user, err := gorm.G[models.User](tx).Where("id = ?", rt.UserId).First(ctx)
		if err != nil {
			return fmt.Errorf("find user with id: %w", err)
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), as.hashCost)
		if err != nil {
			return fmt.Errorf("bcrypt generate from password: %w", err)
		}

		user.Password = string(hashedPassword)
		if err := tx.Save(&user).Error; err != nil {
			return fmt.Errorf("user password update: %w", err)
		}

		// TODO: Logout from active sessions

		return nil
	})
	if err != nil {
		return fmt.Errorf("gorm transaction: %w", err)
	}

	return nil
}
