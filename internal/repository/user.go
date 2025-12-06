// Package repository provides data access layer for the auth service.
package repository

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// UserRepository defines the interface for user data operations.
type UserRepository interface {
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id int64) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	Update(ctx context.Context, user *models.User) error
	GetUserScopes(ctx context.Context, userID int64) (map[string]string, error)
}

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository instance.
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find user by username %s: %w", username, err)
	}
	return &user, nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find user by email %s: %w", email, err)
	}
	return &user, nil
}

func (r *userRepository) FindByID(ctx context.Context, id int64) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).First(&user, id).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find user by id %d: %w", id, err)
	}
	return &user, nil
}

func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user id %d: %w", user.ID, err)
	}
	return nil
}

func (r *userRepository) GetUserScopes(ctx context.Context, userID int64) (map[string]string, error) {
	var user models.User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("failed to find user %d: %w", userID, err)
	}

	if user.RoleID == nil {
		return nil, nil
	}

	var results []models.ScopeResult
	err := r.db.WithContext(ctx).
		Table("role_scopes").
		Select("resources.code as resource_code, role_scopes.permission_level").
		Joins("JOIN resources ON resources.id = role_scopes.resource_id").
		Where("role_scopes.role_id = ?", *user.RoleID).
		Scan(&results).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get scopes for user %d: %w", userID, err)
	}

	scopes := make(map[string]string, len(results))
	for _, result := range results {
		scopes[result.ResourceCode] = result.PermissionLevel
	}

	return scopes, nil
}
