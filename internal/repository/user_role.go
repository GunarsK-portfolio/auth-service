package repository

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// UserRoleRepository handles user-role assignment data access.
type UserRoleRepository interface {
	AssignRole(ctx context.Context, userID int64, roleCode string) error
}

type userRoleRepository struct {
	db *gorm.DB
}

// NewUserRoleRepository creates a new UserRoleRepository instance.
func NewUserRoleRepository(db *gorm.DB) UserRoleRepository {
	return &userRoleRepository{db: db}
}

func (r *userRoleRepository) AssignRole(ctx context.Context, userID int64, roleCode string) error {
	var role models.Role
	if err := r.db.WithContext(ctx).Where("code = ?", roleCode).First(&role).Error; err != nil {
		return fmt.Errorf("failed to find role %s: %w", roleCode, err)
	}

	userRole := &models.UserRole{
		UserID: userID,
		RoleID: role.ID,
	}
	if err := r.db.WithContext(ctx).Create(userRole).Error; err != nil {
		return fmt.Errorf("failed to assign role %s to user %d: %w", roleCode, userID, err)
	}
	return nil
}
