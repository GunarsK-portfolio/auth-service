// Package email publishes emails via RabbitMQ for async delivery.
package email

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/portfolio-common/models"
	"github.com/GunarsK-portfolio/portfolio-common/queue"
	"github.com/GunarsK-portfolio/portfolio-common/renderer"
	"gorm.io/gorm"
)

// Sender defines the interface for sending emails.
type Sender interface {
	SendVerificationEmail(ctx context.Context, recipientEmail, username, verifyURL string) error
	SendPasswordResetEmail(ctx context.Context, recipientEmail, username, resetURL string) error
}

// Client renders email templates, persists them to the database,
// and publishes an event to RabbitMQ for the messaging-service worker.
type Client struct {
	db        *gorm.DB
	publisher queue.Publisher
}

// NewClient creates a new email client.
func NewClient(db *gorm.DB, publisher queue.Publisher) *Client {
	return &Client{
		db:        db,
		publisher: publisher,
	}
}

// SendVerificationEmail renders and queues an email verification email.
func (c *Client) SendVerificationEmail(ctx context.Context, recipientEmail, username, verifyURL string) error {
	return c.send(ctx, models.EmailTypeEmailVerification, recipientEmail, map[string]string{
		"username":   username,
		"verify_url": verifyURL,
	})
}

// SendPasswordResetEmail renders and queues a password reset email.
func (c *Client) SendPasswordResetEmail(ctx context.Context, recipientEmail, username, resetURL string) error {
	return c.send(ctx, models.EmailTypePasswordReset, recipientEmail, map[string]string{
		"username":  username,
		"reset_url": resetURL,
	})
}

func (c *Client) send(ctx context.Context, emailType, recipientEmail string, data map[string]string) error {
	subject, ok := renderer.SubjectForType(emailType)
	if !ok {
		return fmt.Errorf("unsupported email type: %s", emailType)
	}

	html, err := renderer.Render(emailType, data)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	email := &models.Email{
		Type:           emailType,
		RecipientEmail: &recipientEmail,
		Subject:        subject,
		Message:        html,
		Status:         models.EmailStatusPending,
	}

	if err := c.db.WithContext(ctx).Omit("ID", "CreatedAt", "UpdatedAt").Create(email).Error; err != nil {
		return fmt.Errorf("failed to create email record: %w", err)
	}

	event := models.EmailEvent{EmailID: email.ID}
	if err := c.publisher.Publish(ctx, event); err != nil {
		return fmt.Errorf("failed to publish email event: %w", err)
	}

	return nil
}
