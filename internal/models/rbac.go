// Package models contains data models for the auth service.
package models

import "time"

// Role represents a permission group (admin, read-only, etc.).
type Role struct {
	ID        int64     `json:"id" gorm:"primaryKey"`
	Code      string    `json:"code" gorm:"uniqueIndex;not null"`
	Name      string    `json:"name" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName returns the database table name for the Role model.
func (Role) TableName() string {
	return "roles"
}

// Resource represents a protected resource (profile, projects, etc.).
type Resource struct {
	ID        int64     `json:"id" gorm:"primaryKey"`
	Code      string    `json:"code" gorm:"uniqueIndex;not null"`
	Name      string    `json:"name" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName returns the database table name for the Resource model.
func (Resource) TableName() string {
	return "resources"
}

// RoleScope maps a role to a resource with a permission level.
type RoleScope struct {
	RoleID          int64    `json:"role_id" gorm:"primaryKey"`
	ResourceID      int64    `json:"resource_id" gorm:"primaryKey"`
	PermissionLevel string   `json:"permission_level" gorm:"not null;default:none"`
	Role            Role     `json:"-" gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE"`
	Resource        Resource `json:"-" gorm:"foreignKey:ResourceID;constraint:OnDelete:CASCADE"`
}

// TableName returns the database table name for the RoleScope model.
func (RoleScope) TableName() string {
	return "role_scopes"
}

// ScopeResult is used to query scopes with resource code.
type ScopeResult struct {
	ResourceCode    string
	PermissionLevel string
}
