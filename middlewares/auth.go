package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sebsvt/cmu-contest-2024/auth-service/services"
)

func AuthRequired(authSrv services.Authorization) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the token from the request header
		authHeader := c.Get("Authorization")

		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing token",
			})
		}

		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token format",
			})
		}

		// Extract the token without the Bearer prefix
		tokenString := authHeader[len(bearerPrefix):]

		// Use the authorization service to validate the token
		info, err := authSrv.Authorize(tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}
		// Set the user ID in the context for use in handlers
		c.Locals("user_id", info.Subject)
		return c.Next()
	}
}
