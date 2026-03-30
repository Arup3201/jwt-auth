package services

import (
	"context"
	"crypto/rsa"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.com/go-jwt-auth/constants"
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
	refreshDuration time.Duration
	privateKey      *rsa.PrivateKey
	emailChecker    *regexp.Regexp
}

func NewAuthService(db *gorm.DB,
	hCost int,
	privateKey *rsa.PrivateKey,
	sessionDuration time.Duration,
	refreshDuration time.Duration) interfaces.AuthService {

	var emailRegex, _ = regexp.Compile(
		`^[a-zA-Z0-9]+([._-][0-9a-zA-Z]+)*@[a-zA-Z0-9]+([.-][0-9a-zA-Z]+)*\.[a-zA-Z]{2,}$`,
	)

	return &authService{
		db:              db,
		hashCost:        hCost,
		sessionDuration: sessionDuration,
		refreshDuration: refreshDuration,
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
	email, password string) (*interfaces.Tokens, error) {

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
	var accessToken, refreshToken string
	var accessExpiry, refreshExpiry time.Time
	var jwt *utils.JWT

	issuer = ISSUER
	userId = strconv.Itoa(int(user.ID))
	subject = userId

	accessExpiry = time.Now().Add(as.sessionDuration)
	accessClaims := utils.NewClaims(issuer, subject, userId, accessExpiry)
	jwt, err = utils.JWTFromClaims(accessClaims, constants.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("utils jwt from claims: %w", err)
	}

	accessToken, err = jwt.Sign(as.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	refreshExpiry = time.Now().Add(as.refreshDuration)
	refreshClaims := utils.NewClaims(issuer, subject, userId, refreshExpiry)
	jwt, err = utils.JWTFromClaims(refreshClaims, constants.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("utils jwt from claims: %w", err)
	}

	dbToken := models.RefreshToken{
		Jti:       refreshClaims.Jti,
		UserId:    user.ID,
		Revoked:   false,
		CreatedAt: refreshClaims.IssuedAt,
		UpdatedAt: refreshClaims.IssuedAt,
	}
	err = gorm.G[models.RefreshToken](as.db).Create(ctx, &dbToken)
	if err != nil {
		return nil, fmt.Errorf("db refresh token create: %w", err)
	}

	refreshToken, err = jwt.Sign(as.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	return &interfaces.Tokens{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiry,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiry,
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

func (as *authService) GetUser(ctx context.Context, userId string) (models.User, error) {

	var err error
	var user models.User

	user, err = gorm.G[models.User](as.db).
		Where("id = ?", userId).
		First(ctx)
	if err != nil {
		return user, fmt.Errorf("gorm user where clause: %w", err)
	}

	return user, nil
}
