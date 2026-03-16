// Package email provides an HTTP client for sending emails via messaging-api.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/middleware"
	commonModels "github.com/GunarsK-portfolio/portfolio-common/models"
)

// Client sends emails by calling the messaging-api.
type Client struct {
	baseURL     string
	jwtService  jwt.Service
	httpClient  *http.Client
	svcUserID   int64
	svcUserName string
}

// NewClient creates a new email client.
func NewClient(baseURL string, jwtService jwt.Service, svcUserID int64, svcUserName string) *Client {
	return &Client{
		baseURL:     baseURL,
		jwtService:  jwtService,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		svcUserID:   svcUserID,
		svcUserName: svcUserName,
	}
}

type sendEmailRequest struct {
	Type           string            `json:"type"`
	RecipientEmail string            `json:"recipient_email"`
	Data           map[string]string `json:"data"`
}

// SendPasswordResetEmail sends a password reset email via messaging-api.
func (c *Client) SendPasswordResetEmail(ctx context.Context, recipientEmail, username, resetURL string) error {
	return c.send(ctx, commonModels.EmailTypePasswordReset, recipientEmail, map[string]string{
		"username":  username,
		"reset_url": resetURL,
	})
}

// SendVerificationEmail sends an email verification email via messaging-api.
func (c *Client) SendVerificationEmail(ctx context.Context, recipientEmail, username, verifyURL string) error {
	return c.send(ctx, commonModels.EmailTypeEmailVerification, recipientEmail, map[string]string{
		"username":   username,
		"verify_url": verifyURL,
	})
}

func (c *Client) send(ctx context.Context, emailType, recipientEmail string, data map[string]string) error {
	body, err := json.Marshal(sendEmailRequest{
		Type:           emailType,
		RecipientEmail: recipientEmail,
		Data:           data,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create email request: %w", err)
	}

	token, err := c.mintServiceToken()
	if err != nil {
		return fmt.Errorf("failed to mint service token: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("messaging-api returned status %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) mintServiceToken() (string, error) {
	scopes := map[string]string{
		middleware.ResourceEmails: middleware.LevelEdit,
	}
	return c.jwtService.GenerateAccessToken(c.svcUserID, c.svcUserName, scopes)
}
