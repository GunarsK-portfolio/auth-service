// Package repository provides data access layer for the auth service.
package repository

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// OAuthAccountRepository defines operations for OAuth account data.
type OAuthAccountRepository interface {
	FindByProviderAndID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error)
	FindByUserID(ctx context.Context, userID int64) ([]models.OAuthAccount, error)
	Create(ctx context.Context, account *models.OAuthAccount) error
}

type oauthAccountRepository struct {
	db *gorm.DB
}

// NewOAuthAccountRepository creates a new OAuthAccountRepository instance.
func NewOAuthAccountRepository(db *gorm.DB) OAuthAccountRepository {
	return &oauthAccountRepository{db: db}
}

func (r *oauthAccountRepository) FindByProviderAndID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error) {
	var account models.OAuthAccount
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&account).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find oauth account for %s/%s: %w", provider, providerUserID, err)
	}
	return &account, nil
}

func (r *oauthAccountRepository) FindByUserID(ctx context.Context, userID int64) ([]models.OAuthAccount, error) {
	var accounts []models.OAuthAccount
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&accounts).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find oauth accounts for user %d: %w", userID, err)
	}
	return accounts, nil
}

func (r *oauthAccountRepository) Create(ctx context.Context, account *models.OAuthAccount) error {
	if err := r.db.WithContext(ctx).Create(account).Error; err != nil {
		return fmt.Errorf("failed to create oauth account: %w", err)
	}
	return nil
}
