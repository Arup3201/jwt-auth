package interfaces

import (
	"context"

	"example.com/jwt-auth/models"
)

type AuthService interface {
	Register(ctx context.Context, email, fullName, password string) (uint, error)
	Login(ctx context.Context, email, password string) error
	ResetPassword(ctx context.Context, token, password string) error
	Logout(ctx context.Context, id string) error
	GetUserFromSession(ctx context.Context, sessionId string) (models.User, error)
}

type EmailService interface {
	SendVerificationEmail(ctx context.Context, userId, email, fullName string) error
	VerifyEmail(ctx context.Context, token string) error
	GetEmailVerificationStatus(ctx context.Context, email string) (bool, error)
	SendPasswordResetEmail(ctx context.Context, email string) error
}
