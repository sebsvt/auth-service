package services

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/sebsvt/cmu-contest-2024/auth-service/externals"
	"github.com/sebsvt/cmu-contest-2024/auth-service/logs"
	"github.com/sebsvt/cmu-contest-2024/auth-service/repository"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

// userService implements the UserService interface.
type userService struct {
	user_repo repository.UserRepository
}

// NewUserService returns a new instance of userService.
func NewUserService(user_repo repository.UserRepository) UserService {
	return userService{user_repo: user_repo}
}

// CreateNewUser creates a new user after validating the input data.
func (srv userService) CreateNewUser(new_user UserCreatedModel) (uuid.UUID, error) {
	// Validate email
	if !validateEmail(new_user.Email) {
		return uuid.Nil, ErrInvalidEmail
	}

	// Validate password
	if err := validatePassword(new_user.Password); err != nil {
		logs.Error(err)
		return uuid.Nil, ErrInsecurePassword
	}

	// Check if the email is already in use
	existing_user, err := srv.user_repo.FromEmail(new_user.Email)
	if err != nil && err != sql.ErrNoRows {
		logs.Error(err)
		return uuid.Nil, ErrUnexpectedError
	}
	if existing_user != nil {
		return uuid.Nil, ErrUserEmailAlreadyInUse
	}

	salt, err := externals.GenerateSalt()
	if err != nil {
		logs.Error(err)
		return uuid.Nil, ErrUnexpectedError
	}

	// Hash the password using bcrypt
	hashed_password := externals.HashPassword(new_user.Password, salt)

	// Create a new user record
	user_id := uuid.New()
	user := repository.User{
		UserID:         user_id,
		Email:          new_user.Email,
		HashedPassword: string(hashed_password),
		Salt:           salt,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := srv.user_repo.Create(user); err != nil {
		logs.Error(err)
		return uuid.Nil, ErrUnexpectedError
	}

	return user_id, nil
}

// DeleteFromUserID deletes a user by their ID.
func (srv userService) DeleteFromUserID(user_id uuid.UUID) error {
	if err := srv.user_repo.DeleteByUserID(user_id); err != nil {
		logs.Error(err)
		return err
	}
	return nil
}

// FromID retrieves a user's information by their ID.
func (srv userService) FromID(user_id uuid.UUID) (*UserModel, error) {
	user, err := srv.user_repo.FromUserID(user_id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		logs.Error(err)
		return nil, ErrUnexpectedError
	}
	return &UserModel{
		UserID:    user.UserID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (srv userService) UpdateEmailFromUserID(user_id uuid.UUID, new_email string) error {
	// Validate the new email
	if !validateEmail(new_email) {
		return ErrInvalidEmail
	}

	fmt.Println(new_email)
	// Retrieve the user
	user, err := srv.user_repo.FromUserID(user_id)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrUserNotFound
		}
		logs.Error(err)
		return ErrUnexpectedError
	}

	// Check if the new email is already in use
	existing_user, err := srv.user_repo.FromEmail(new_email)
	if err != nil && err != sql.ErrNoRows {
		logs.Error(err)
		return ErrUnexpectedError
	}
	if existing_user != nil {
		return ErrUserEmailAlreadyInUse
	}

	if new_email == user.Email {
		return ErrCanNotChangeToSameEmail
	}
	// Update the email
	user.Email = new_email
	user.UpdatedAt = time.Now()
	if err := srv.user_repo.Update(*user); err != nil {
		logs.Error(err)
		return ErrUnexpectedError
	}

	return nil
}

// UpdatePasswordFromUserID updates a user's password by their ID.
func (srv userService) UpdatePasswordFromUserID(user_id uuid.UUID, new_password string) error {
	// Validate the new password
	if err := validatePassword(new_password); err != nil {
		logs.Error(err)
		return ErrInsecurePassword
	}

	// Retrieve the user
	user, err := srv.user_repo.FromUserID(user_id)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrUserNotFound
		}
		logs.Error(err)
		return ErrUnexpectedError
	}

	// Generate a new salt and hash the new password
	salt, err := externals.GenerateSalt()
	if err != nil {
		logs.Error(err)
		return ErrUnexpectedError
	}
	hashed_password := externals.HashPassword(new_password, salt)

	// Update the password
	user.HashedPassword = string(hashed_password)
	user.Salt = salt
	user.UpdatedAt = time.Now()
	if err := srv.user_repo.Update(*user); err != nil {
		logs.Error(err)
		return ErrUnexpectedError
	}

	return nil
}

// validateEmail checks if the provided email address is valid.
func validateEmail(email string) bool {
	// Simple regex for email validation
	var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	return emailRegex.MatchString(email)
}

// validatePassword checks if the provided password meets the required criteria.
func validatePassword(password string) error {
	// Define your password policy
	// entropy := passwordvalidator.GetEntropy("a longer password")
	const minEntropyBits = 60
	// Validate the password
	return passwordvalidator.Validate(password, minEntropyBits)
}
