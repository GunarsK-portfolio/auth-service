// Package repository provides data access layer for the auth service.
package repository

import (
	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"gorm.io/gorm"
)

// UserRepository defines the interface for user data operations.
type UserRepository interface {
	FindByUsername(username string) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
	FindByID(id int64) (*models.User, error)
	Create(user *models.User) error
	Update(user *models.User) error
}

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository instance.
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByID(id int64) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}
