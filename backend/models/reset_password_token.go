package models

import "time"

type PasswordResetToken struct {
	UserId      uint
	HashedToken string `gorm:"primaryKey"`
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedAt   time.Time
}
