package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"example.com/go-jwt-auth/models"
	"example.com/go-jwt-auth/utils"
	"github.com/resend/resend-go/v3"
	"gorm.io/gorm"
)

type emailService struct {
	client *resend.Client
	db     *gorm.DB
}

func NewEmailService(db *gorm.DB, resendApiKey string) *emailService {

	client := resend.NewClient(resendApiKey)

	return &emailService{
		client: client,
		db:     db,
	}
}

func (es *emailService) SendVerificationEmail(ctx context.Context,
	userId, email, fullName string) error {

	token, err := utils.GenerateHashedToken(32)
	if err != nil {
		return fmt.Errorf("get hashed token: %w", err)
	}

	tokenSHA := utils.HashToken(token)
	ev := models.EmailVerification{
		UserId:      userId,
		HashedToken: tokenSHA,
		ExpiresAt:   time.Now().Add(2 * time.Minute), // TODO: set from main
	}
	err = gorm.G[models.EmailVerification](es.db).Create(ctx, &ev)
	if err != nil {
		return fmt.Errorf("gorm create: %w", err)
	}

	// TODO: dynamic link
	verificationLink := fmt.Sprintf("http://localhost:8080/api/verify-email?token=%s", token)
	html := fmt.Sprintf("Hello %s, Here is your email verification link: \n<a href='%s'>Click to verify</a>\n", fullName, verificationLink)

	params := &resend.SendEmailRequest{
		From:    "Arup <hello@contact.itsdeployedbyme.dpdns.org>",
		To:      []string{email},
		Html:    html,
		Subject: "Email verification",
		ReplyTo: "hello@contact.itsdeployedbyme.dpdns.org",
	}

	sent, err := es.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("email client send: %w", err)
	}

	log.Printf("[INFO] Email sent: %s\n", sent.Id)

	return nil
}

func (es *emailService) VerifyEmail(ctx context.Context, token string) error {

	tokenSHA := utils.HashToken(token)
	now := time.Now().UTC()

	err := es.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ev, err := gorm.G[models.EmailVerification](tx).
			Where("hashed_token = ? AND used_at IS NULL AND expires_at >= ?",
				tokenSHA, now).
			First(ctx)
		if err != nil {
			return fmt.Errorf("gorm find hashed token: %w", err)
		}

		ev.UsedAt = &now
		if err := tx.Save(&ev).Error; err != nil {
			return fmt.Errorf("email verification used at update: %w", err)
		}

		user, err := gorm.G[models.User](tx).Where("id = ?", ev.UserId).First(ctx)
		if err != nil {
			return fmt.Errorf("gorm find user with id: %w", err)
		}

		user.EmailVerified = true
		if err := tx.Save(&user).Error; err != nil {
			return fmt.Errorf("user mark email verified update: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("gorm transaction: %w", err)
	}

	return nil
}

func (es *emailService) GetEmailVerificationStatus(ctx context.Context, email string) (bool, error) {

	user, err := gorm.G[models.User](es.db).Where("email = ?", email).First(ctx)
	if err != nil {
		return false, fmt.Errorf("gorm find user with id: %w", err)
	}

	return user.EmailVerified, nil
}

func (es *emailService) SendPasswordResetEmail(ctx context.Context, email string) error {

	user, err := gorm.G[models.User](es.db).Where("email = ?", email).First(ctx)
	if err != nil {
		return fmt.Errorf("gorm find user with id: %w", err)
	}

	/* Invalidate active password reset tokens */
	resetTokens, err := gorm.G[models.PasswordResetToken](es.db).Where("user_id = ?", user.ID).Find(ctx)
	if err != nil {
		return fmt.Errorf("find previous active password reset tokens with user_id: %w", err)
	}
	for _, t := range resetTokens {
		t.ExpiresAt = time.Unix(0, 0)
		if err := es.db.Save(&t).Error; err != nil {
			return fmt.Errorf("expire password reset token: %w", err)
		}
	}

	token, err := utils.GenerateHashedToken(32)
	if err != nil {
		return fmt.Errorf("generate hashed token: %w", err)
	}

	tokenSHA := utils.HashToken(token)
	resetToken := models.PasswordResetToken{
		UserId:      user.ID,
		HashedToken: tokenSHA,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	err = gorm.G[models.PasswordResetToken](es.db).Create(ctx, &resetToken)
	if err != nil {
		return fmt.Errorf("password reset token create: %w", err)
	}

	resetLink := fmt.Sprintf("http://localhost:5173/reset-password?token=%s", token)
	html := fmt.Sprintf("Hello %s, Here is your password reset link: \n<a href='%s'>Click to reset password</a>\n", user.FullName, resetLink)

	params := &resend.SendEmailRequest{
		From:    "Arup <hello@contact.itsdeployedbyme.dpdns.org>",
		To:      []string{email},
		Html:    html,
		Subject: "Email verification",
		ReplyTo: "hello@contact.itsdeployedbyme.dpdns.org",
	}

	sent, err := es.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	log.Printf("[INFO] Reset password email sent: %s\n", sent.Id)

	return nil
}
