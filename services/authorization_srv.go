package services

import (
	"database/sql"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sebsvt/cmu-contest-2024/auth-service/externals"
	"github.com/sebsvt/cmu-contest-2024/auth-service/logs"
	"github.com/sebsvt/cmu-contest-2024/auth-service/repository"
)

type auth struct {
	user_repo            repository.UserRepository
	secret               []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewAuth creates a new auth service with the given repository, secret, and token durations.
func NewAuth(user_repo repository.UserRepository, secret []byte, accessTokenDuration, refreshTokenDuration time.Duration) Authorization {
	return auth{
		user_repo:            user_repo,
		secret:               secret,
		accessTokenDuration:  accessTokenDuration,
		refreshTokenDuration: refreshTokenDuration,
	}
}

// SignIn signs in a user by validating their credentials and issuing new tokens.
func (srv auth) SignIn(email string, password string) (string, string, error) {
	if !validateEmail(email) {
		return "", "", ErrInvalidEmail
	}
	user, err := srv.user_repo.FromEmail(email)
	if err != nil {
		logs.Error(err)
		if err == sql.ErrNoRows {
			return "", "", ErrAuthenticationFailed
		}
		return "", "", ErrUnexpectedError
	}
	if !externals.ComparePassword(user.HashedPassword, password, user.Salt) {
		return "", "", ErrAuthenticationFailed
	}

	access_token, refresh_token, err := srv.Tokenize(user.UserID.String())
	if err != nil {
		logs.Error(err)
		return "", "", ErrAuthenticationFailed
	}

	if err := srv.user_repo.UpdateRefreshToken(user.UserID, refresh_token, time.Now().Add(srv.refreshTokenDuration)); err != nil {
		logs.Error(err)
		return "", "", ErrAuthenticationFailed
	}

	return access_token, refresh_token, nil
}

// Tokenize creates a new access and refresh token for the given subject.
func (srv auth) Tokenize(subject string) (string, string, error) {
	access_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  subject,
		"exp":  time.Now().Add(srv.accessTokenDuration).Unix(),
		"type": AccessToken,
	})

	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  subject,
		"exp":  time.Now().Add(srv.refreshTokenDuration).Unix(),
		"type": RefreshToken,
	})

	signedAccessToken, err := access_token.SignedString(srv.secret)
	if err != nil {
		return "", "", err
	}

	signedRefreshToken, err := refresh_token.SignedString(srv.secret)
	if err != nil {
		return "", "", err
	}

	return signedAccessToken, signedRefreshToken, nil
}

// Authorize validates an access token and returns the associated user information.
func (srv auth) Authorize(accessToken string) (Info, error) {
	token, err := srv.parseAndValidate(accessToken)
	if err != nil {
		return Info{}, err
	}
	return ClaimToInfo(token.Claims.(jwt.MapClaims))
}

// Refresh validates a refresh token, checks it against the database, and issues a new access token.
func (srv auth) Refresh(refreshToken string) (string, string, error) {
	token, err := srv.parseAndValidate(refreshToken)
	if err != nil {
		logs.Error(err)
		return "", "", mapToAuthErrors(err)
	}

	subject, err := token.Claims.(jwt.MapClaims).GetSubject()
	if err != nil {
		logs.Error(err)
		return "", "", mapToAuthErrors(err)
	}

	// Check refresh token in the database
	userID, err := uuid.Parse(subject)
	if err != nil {
		logs.Error(err)
		return "", "", ErrBadClaim
	}

	user, err := srv.user_repo.FromUserID(userID)
	if err != nil {
		logs.Error(err)
		if err == sql.ErrNoRows {
			return "", "", ErrUserNotFound
		}
		return "", "", ErrUnexpectedError
	}

	if user.RefreshToken != refreshToken {
		return "", "", ErrBadClaim
	}

	if user.RefreshTokenExpiry.Before(time.Now()) {
		return "", "", ErrTokenExpired
	}

	new_access_token, new_refresh_token, err := srv.Tokenize(subject)
	if err != nil {
		logs.Error(err)
		return "", "", err
	}

	if err := srv.user_repo.UpdateRefreshToken(user.UserID, new_refresh_token, time.Now().Add(srv.refreshTokenDuration)); err != nil {
		logs.Error(err)
		return "", "", ErrAuthenticationFailed
	}

	return new_access_token, new_refresh_token, nil
}

func (srv *auth) parseAndValidate(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrAuthorizationFailed
		}
		return srv.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if err := srv.validateToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

func (srv *auth) validateToken(token *jwt.Token) error {
	if !token.Valid {
		return ErrAuthorizationFailed
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ErrBadClaim
	}
	_, err := claims.GetSubject()
	if err != nil {
		return ErrBadClaim
	}
	return nil
}

func ClaimToInfo(claims jwt.MapClaims) (Info, error) {
	subject, err := claims.GetSubject()
	if err != nil {
		return Info{}, ErrBadClaim
	}
	expiration, err := claims.GetExpirationTime()
	if err != nil {
		return Info{}, ErrBadClaim
	}
	tokenType, is := claims["type"].(string)
	if !is {
		return Info{}, ErrBadClaim
	}
	return Info{
		Subject:        subject,
		ExpirationDate: expiration.Time,
		Type:           TokenType(tokenType),
	}, nil
}

func mapToAuthErrors(err error) error {
	if errors.Is(err, jwt.ErrTokenExpired) {
		return ErrTokenExpired
	}
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return ErrInvalidSignature
	}
	return ErrBadClaim
}
