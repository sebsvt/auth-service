package handlers

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/sebsvt/cmu-contest-2024/auth-service/services"
)

var (
	ErrInvalidRequestBody = errors.New("invalid request body")
)

type UserCrendentail struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshTokenBody struct {
	RefreshToken string `json:"refresh_token"`
}

type authHandler struct {
	user_srv services.UserService
	auth_srv services.Authorization
}

func NewAuthHandler(user_srv services.UserService, auth_srv services.Authorization) authHandler {
	return authHandler{
		user_srv: user_srv,
		auth_srv: auth_srv,
	}
}

func (h authHandler) SignUp(c *fiber.Ctx) error {
	var new_user services.UserCreatedModel
	if err := c.BodyParser(&new_user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrInvalidRequestBody.Error(),
		})
	}

	user_id, err := h.user_srv.CreateNewUser(new_user)
	if err != nil {
		switch err {
		case services.ErrUserEmailAlreadyInUse,
			services.ErrInsecurePassword,
			services.ErrInvalidEmail:
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	return c.JSON(fiber.Map{
		"user_id": user_id.String(),
	})
}

func (h authHandler) SignIn(c *fiber.Ctx) error {
	var user_crendentail UserCrendentail
	if err := c.BodyParser(&user_crendentail); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrInvalidRequestBody.Error(),
		})
	}
	access_token, refresh_token, err := h.auth_srv.SignIn(user_crendentail.Email, user_crendentail.Password)
	if err != nil {
		switch err {
		case services.ErrAuthenticationFailed, services.ErrInvalidEmail:
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})

		default:
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}
	return c.JSON(fiber.Map{
		"access_token":  access_token,
		"refresh_token": refresh_token,
		"type":          "Bearer",
	})
}

func (h authHandler) RefreshToken(c *fiber.Ctx) error {
	var refresh_token RefreshTokenBody
	if err := c.BodyParser(&refresh_token); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrInvalidRequestBody.Error(),
		})
	}
	new_access_token, new_refresh_token, err := h.auth_srv.Refresh(refresh_token.RefreshToken)
	if err != nil {
		switch err {
		case services.ErrUserNotFound, services.ErrBadClaim, services.ErrInvalidSignature, services.ErrTokenExpired:
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": services.ErrUnexpectedError,
			})
		}
	}
	return c.JSON(fiber.Map{
		"access_token":  new_access_token,
		"refresh_token": new_refresh_token,
		"type":          "Bearer",
	})
}

func (h authHandler) Verify(c *fiber.Ctx) error {
	user_id, ok := c.Locals("user_id").(string)
	if !ok || user_id == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": services.ErrAuthorizationFailed.Error(),
		})
	}
	return c.JSON(fiber.Map{
		"user_id": user_id,
	})
}
