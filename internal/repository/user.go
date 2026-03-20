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
	FindRoleByCode(ctx context.Context, code string) (*models.Role, error)
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

var levelValues = map[string]int{"none": 0, "read": 1, "edit": 2, "delete": 3}

func (r *userRepository) GetUserScopes(ctx context.Context, userID int64) (map[string]string, error) {
	var results []models.ScopeResult
	err := r.db.WithContext(ctx).
		Table("user_roles").
		Select("resources.code as resource_code, role_scopes.permission_level").
		Joins("JOIN role_scopes ON role_scopes.role_id = user_roles.role_id").
		Joins("JOIN resources ON resources.id = role_scopes.resource_id").
		Where("user_roles.user_id = ?", userID).
		Scan(&results).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get scopes for user %d: %w", userID, err)
	}

	scopes := make(map[string]string)
	for _, result := range results {
		existing, ok := scopes[result.ResourceCode]
		if !ok || levelValues[result.PermissionLevel] > levelValues[existing] {
			scopes[result.ResourceCode] = result.PermissionLevel
		}
	}

	for k, v := range scopes {
		if v == "none" {
			delete(scopes, k)
		}
	}

	return scopes, nil
}

func (r *userRepository) FindRoleByCode(ctx context.Context, code string) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).Where("code = ?", code).First(&role).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find role by code %s: %w", code, err)
	}
	return &role, nil
}
