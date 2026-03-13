package services

import (
	"context"
	"time"

	"example.com/jwt-auth/interfaces"
	"example.com/jwt-auth/models"
	"gorm.io/gorm"
)

type authService struct {
}

func NewAuthService(db *gorm.DB,
	hCost int,
	sessionDuration time.Duration) interfaces.AuthService {

	return &authService{}
}

func (as *authService) Register(ctx context.Context, email, fullName, password string) (uint, error) {
	panic("TODO")
}

func (as *authService) Login(ctx context.Context, email, password string) error {
	panic("TODO")
}

func (as *authService) ResetPassword(ctx context.Context, token, password string) error {
	panic("TODO")
}

func (as *authService) Logout(ctx context.Context, id string) error {
	panic("TODO")
}

func (as *authService) GetUserFromSession(ctx context.Context, sessionId string) (models.User, error) {
	panic("TODO")
}
