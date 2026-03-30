package models

import "time"

type RefreshToken struct {
	Jti       string `gorm:"primaryKey"`
	UserId    uint
	Revoked   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
