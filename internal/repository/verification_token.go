// Package repository provides data access layer for the auth service.
package repository

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// VerificationTokenRepository defines operations for verification tokens.
type VerificationTokenRepository interface {
	Create(ctx context.Context, token *models.VerificationToken) error
	FindByToken(ctx context.Context, token string) (*models.VerificationToken, error)
	FindByUserID(ctx context.Context, userID int64) (*models.VerificationToken, error)
	DeleteByUserID(ctx context.Context, userID int64) error
}

type verificationTokenRepository struct {
	db *gorm.DB
}

// NewVerificationTokenRepository creates a new VerificationTokenRepository instance.
func NewVerificationTokenRepository(db *gorm.DB) VerificationTokenRepository {
	return &verificationTokenRepository{db: db}
}

func (r *verificationTokenRepository) Create(ctx context.Context, token *models.VerificationToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}
	return nil
}

func (r *verificationTokenRepository) FindByToken(ctx context.Context, token string) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("token = ?", token).First(&vt).Error; err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}
	return &vt, nil
}

func (r *verificationTokenRepository) FindByUserID(ctx context.Context, userID int64) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&vt).Error; err != nil {
		return nil, fmt.Errorf("failed to find verification token for user %d: %w", userID, err)
	}
	return &vt, nil
}

func (r *verificationTokenRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.VerificationToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete verification tokens for user %d: %w", userID, err)
	}
	return nil
}
