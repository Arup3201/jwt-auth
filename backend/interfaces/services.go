package interfaces

import (
	"context"
	"time"
)

type Token struct {
	Value     string
	ExpiresAt time.Time
}

type AuthService interface {
	Register(ctx context.Context, email, fullName, password string) (uint, error)
	Login(ctx context.Context, email, password string) (*Token, error)
	ResetPassword(ctx context.Context, token, password string) error
}

type EmailService interface {
	SendVerificationEmail(ctx context.Context, userId, email, fullName string) error
	VerifyEmail(ctx context.Context, token string) error
	GetEmailVerificationStatus(ctx context.Context, email string) (bool, error)
	SendPasswordResetEmail(ctx context.Context, email string) error
}
