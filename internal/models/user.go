// Package models contains data models for the auth service.
package models

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID           int64     `json:"id" gorm:"primaryKey"`
	Username     string    `json:"username" gorm:"uniqueIndex;not null"`
	Email        string    `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash string    `json:"-" gorm:"not null"`
	RoleID       *int      `json:"role_id" gorm:"column:role_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName returns the database table name for the User model.
func (User) TableName() string {
	return "users"
}
