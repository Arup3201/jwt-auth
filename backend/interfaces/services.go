package interfaces

import (
	"context"
	"time"

	"example.com/go-jwt-auth/models"
)

type Tokens struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

type AuthService interface {
	Register(ctx context.Context, email, fullName, password string) (uint, error)
	Login(ctx context.Context, email, password string) (*Tokens, error)
	Refresh(ctx context.Context, token string) (*Tokens, error)
	ResetPassword(ctx context.Context, token, password string) error
	Logout(ctx context.Context, token string) error
	GetUser(ctx context.Context, userId string) (models.User, error)
}

type EmailService interface {
	SendVerificationEmail(ctx context.Context, userId, email, fullName string) error
	VerifyEmail(ctx context.Context, token string) error
	GetEmailVerificationStatus(ctx context.Context, email string) (bool, error)
	SendPasswordResetEmail(ctx context.Context, email string) error
}
