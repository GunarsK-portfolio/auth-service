// Package models contains data models for the auth service.
package models

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID            int64     `json:"id" gorm:"primaryKey"`
	Username      string    `json:"username" gorm:"uniqueIndex;not null"`
	Email         string    `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash  string    `json:"-" gorm:"not null"`
	EmailVerified bool      `json:"email_verified" gorm:"not null;default:false"`
	DisplayName   *string   `json:"display_name" gorm:"column:display_name"`
	RoleID        *int      `json:"role_id" gorm:"column:role_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// VerificationToken stores email verification tokens for users.
type VerificationToken struct {
	ID        int64     `json:"id" gorm:"primaryKey"`
	UserID    int64     `json:"user_id" gorm:"not null"`
	Email     string    `json:"email" gorm:"not null"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName returns the database table name for the VerificationToken model.
func (VerificationToken) TableName() string {
	return "verification_tokens"
}

// TableName returns the database table name for the User model.
func (User) TableName() string {
	return "users"
}
