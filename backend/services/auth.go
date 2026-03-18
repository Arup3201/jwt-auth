package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"example.com/go-jwt-auth/interfaces"
	"example.com/go-jwt-auth/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type authService struct {
	db              *gorm.DB
	hashCost        int
	sessionDuration time.Duration
	emailChecker    *regexp.Regexp
}

func NewAuthService(db *gorm.DB,
	hCost int,
	sessionDuration time.Duration) interfaces.AuthService {

	var emailRegex, _ = regexp.Compile(
		`^[a-zA-Z0-9]+([._-][0-9a-zA-Z]+)*@[a-zA-Z0-9]+([.-][0-9a-zA-Z]+)*\.[a-zA-Z]{2,}$`,
	)

	return &authService{
		db:              db,
		hashCost:        hCost,
		sessionDuration: sessionDuration,
		emailChecker:    emailRegex,
	}
}

func (as *authService) Register(ctx context.Context, email, fullName, password string) (uint, error) {
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
