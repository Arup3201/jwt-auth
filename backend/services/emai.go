package services

import (
	"context"

	"example.com/jwt-auth/interfaces"
	"gorm.io/gorm"
)

type emailService struct {
}

func NewEmailService(db *gorm.DB, resendApiKey string) interfaces.EmailService {

	return &emailService{}
}

func (es *emailService) SendVerificationEmail(ctx context.Context, userId, email, fullName string) error {
	panic("TODO")
}

func (es *emailService) VerifyEmail(ctx context.Context, token string) error {
	panic("TODO")
}

func (es *emailService) GetEmailVerificationStatus(ctx context.Context, email string) (bool, error) {
	panic("TODO")
}

func (es *emailService) SendPasswordResetEmail(ctx context.Context, email string) error {
	panic("TODO")
}
