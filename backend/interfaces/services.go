package interfaces

import (
	"context"
)

type AuthService interface {
	Register(ctx context.Context, email, fullName, password string) (uint, error)
}

type EmailService interface {
	SendVerificationEmail(ctx context.Context, userId, email, fullName string) error
	VerifyEmail(ctx context.Context, token string) error
	GetEmailVerificationStatus(ctx context.Context, email string) (bool, error)
	SendPasswordResetEmail(ctx context.Context, email string) error
}
