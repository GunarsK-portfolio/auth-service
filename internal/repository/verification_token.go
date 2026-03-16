// Package repository provides data access layer for the auth service.
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// VerificationTokenRepository defines operations for verification tokens.
type VerificationTokenRepository interface {
	Create(ctx context.Context, token *models.VerificationToken) error
	FindByToken(ctx context.Context, tokenHash string) (*models.VerificationToken, error)
	FindByUserID(ctx context.Context, userID int64) (*models.VerificationToken, error)
	FindByTokenAndType(ctx context.Context, tokenHash, tokenType string) (*models.VerificationToken, error)
	FindByUserIDAndType(ctx context.Context, userID int64, tokenType string) (*models.VerificationToken, error)
	DeleteByUserID(ctx context.Context, userID int64) error
	DeleteByUserIDAndType(ctx context.Context, userID int64, tokenType string) error
	MarkUsed(ctx context.Context, id int64) error
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

func (r *verificationTokenRepository) FindByToken(ctx context.Context, tokenHash string) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("token = ? AND used_at IS NULL", tokenHash).First(&vt).Error; err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}
	return &vt, nil
}

func (r *verificationTokenRepository) FindByUserID(ctx context.Context, userID int64) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("user_id = ? AND used_at IS NULL", userID).First(&vt).Error; err != nil {
		return nil, fmt.Errorf("failed to find verification token for user %d: %w", userID, err)
	}
	return &vt, nil
}

func (r *verificationTokenRepository) FindByTokenAndType(ctx context.Context, tokenHash, tokenType string) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("token = ? AND type = ? AND used_at IS NULL", tokenHash, tokenType).First(&vt).Error; err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}
	return &vt, nil
}

func (r *verificationTokenRepository) FindByUserIDAndType(ctx context.Context, userID int64, tokenType string) (*models.VerificationToken, error) {
	var vt models.VerificationToken
	if err := r.db.WithContext(ctx).Where("user_id = ? AND type = ? AND used_at IS NULL", userID, tokenType).First(&vt).Error; err != nil {
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

func (r *verificationTokenRepository) DeleteByUserIDAndType(ctx context.Context, userID int64, tokenType string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ? AND type = ?", userID, tokenType).Delete(&models.VerificationToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete verification tokens for user %d: %w", userID, err)
	}
	return nil
}

func (r *verificationTokenRepository) MarkUsed(ctx context.Context, id int64) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&models.VerificationToken{}).Where("id = ? AND used_at IS NULL", id).Update("used_at", now)
	if result.Error != nil {
		return fmt.Errorf("failed to mark token %d as used: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("token %d already consumed", id)
	}
	return nil
}
