package services

import (
	"errors"
	"time"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrAuthorizationFailed  = errors.New("authorization failed")
	ErrBadClaim             = errors.New("bad jwt claim")
	ErrTokenExpired         = errors.New("token is expired")
	ErrInvalidSignature     = errors.New("signature is invalid")
	ErrInvalidCredentials   = errors.New("invalid credentials")
)

type TokenType string

var (
	AccessToken  TokenType = "access-token"
	RefreshToken TokenType = "refresh-token"
)

type Info struct {
	Subject        string    `json:"subject"`
	ExpirationDate time.Time `json:"expirationDate"`
	Type           TokenType `json:"type"`
}

type Authorization interface {
	SignIn(email string, password string) (string, string, error)
	Authorize(accessToken string) (Info, error)
	// Tokenize return access and refresh token in order
	Tokenize(subject string) (string, string, error)
	// Refresh gets the refresh token and generates a new access token
	Refresh(refreshToken string) (string, string, error)
}
