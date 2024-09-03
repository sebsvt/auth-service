package repository

import (
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepositoryDB(db *sqlx.DB) UserRepository {
	return userRepository{db: db}
}

// Create implements UserRepository.
func (repo userRepository) Create(entity User) error {
	query := "insert into users (user_id, email, hashed_password, salt, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)"
	_, err := repo.db.Exec(query, entity.UserID, entity.Email, entity.HashedPassword, entity.Salt, entity.CreatedAt, entity.UpdatedAt)
	return err
}

// DeleteByUserID implements UserRepository.
func (repo userRepository) DeleteByUserID(user_id uuid.UUID) error {
	query := "delete from users where user_id=$1"
	_, err := repo.db.Exec(query, user_id)
	return err
}

// FromEmail implements UserRepository.
func (repo userRepository) FromEmail(email string) (*User, error) {
	var user User
	query := "select user_id, email, hashed_password, salt, created_at, updated_at from users where email=$1"
	if err := repo.db.Get(&user, query, email); err != nil {
		return nil, err
	}
	return &user, nil
}

// FromUserID implements UserRepository.
func (repo userRepository) FromUserID(user_id uuid.UUID) (*User, error) {
	var user User
	query := "select user_id, email, hashed_password, salt,  refresh_token, refresh_token_expiry, created_at, updated_at from users where user_id=$1"
	if err := repo.db.Get(&user, query, user_id); err != nil {
		return nil, err
	}
	return &user, nil
}

// Update implements UserRepository.
func (repo userRepository) Update(entity User) error {
	query := `
		update users
		set email=$1, hashed_password=$2, updated_at=$3
		where user_id=$4
	`
	_, err := repo.db.Exec(query, entity.Email, entity.HashedPassword, entity.UpdatedAt, entity.UserID)
	return err
}

func (repo userRepository) UpdateRefreshToken(userID uuid.UUID, refreshToken string, expiry time.Time) error {
	query := `
		update users
		set refresh_token=$1, refresh_token_expiry=$2 where user_id=$3`
	_, err := repo.db.Exec(query, refreshToken, expiry, userID)
	return err
}
