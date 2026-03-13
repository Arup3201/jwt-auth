package models

import "time"

type EmailVerification struct {
	UserId      string
	HashedToken string `gorm:"primaryKey"`
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedAt   time.Time
}
