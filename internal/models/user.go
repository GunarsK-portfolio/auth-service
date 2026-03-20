// Package models contains data models for the auth service.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	TokenTypeEmailVerification = "email_verification" //nolint:gosec // Not a credential
	TokenTypePasswordReset     = "password_reset"     //nolint:gosec // Not a credential
)

// HashToken returns the SHA-256 hex digest of a raw token string.
// Used to hash tokens before DB storage and before DB lookup.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// User represents an authenticated user in the system.
type User struct {
	ID            int64     `json:"id" gorm:"primaryKey"`
	Username      string    `json:"username" gorm:"uniqueIndex;not null"`
	Email         string    `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash  *string   `json:"-"`
	EmailVerified bool      `json:"email_verified" gorm:"not null;default:false"`
	DisplayName   *string   `json:"display_name" gorm:"column:display_name"`
	RoleID        *int      `json:"role_id" gorm:"column:role_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// VerificationToken stores hashed tokens for email verification and password reset.
// Raw tokens exist only in email URLs; the DB stores SHA-256 hashes.
type VerificationToken struct {
	ID        int64      `json:"id" gorm:"primaryKey"`
	UserID    int64      `json:"user_id" gorm:"not null"`
	Email     string     `json:"email" gorm:"not null"`
	Token     string     `json:"token" gorm:"uniqueIndex;not null"`
	Type      string     `json:"type" gorm:"not null;default:email_verification"`
	ExpiresAt *time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// TableName returns the database table name for the VerificationToken model.
func (VerificationToken) TableName() string {
	return "verification_tokens"
}

// OAuthAccount represents an external OAuth provider identity linked to a user.
type OAuthAccount struct {
	ID             int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	Provider       string    `json:"provider" gorm:"not null"`
	ProviderUserID string    `json:"provider_user_id" gorm:"not null"`
	UserID         int64     `json:"user_id" gorm:"not null"`
	Email          string    `json:"email" gorm:"not null"`
	CreatedAt      time.Time `json:"created_at"`
}

// TableName returns the database table name for the OAuthAccount model.
func (OAuthAccount) TableName() string {
	return "auth.oauth_accounts"
}

// TableName returns the database table name for the User model.
func (User) TableName() string {
	return "users"
}
