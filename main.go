package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sebsvt/cmu-contest-2024/auth-service/handlers"
	"github.com/sebsvt/cmu-contest-2024/auth-service/repository"
	"github.com/sebsvt/cmu-contest-2024/auth-service/services"
)

func main() {
	godotenv.Load()
	db := initDB()
	user_repo := repository.NewUserRepositoryDB(db)
	user_srv := services.NewUserService(user_repo)
	auth_srv := services.NewAuth(user_repo, []byte(os.Getenv("SECRET_KEY")), time.Minute*15, time.Hour*(24*7))
	user_handler := handlers.NewAuthHandler(user_srv, auth_srv)

	app := fiber.New()

	api := app.Group("/api")

	api.Get("/auth/verify", user_handler.Verify)
	api.Post("/auth/signup", user_handler.SignUp)
	api.Post("/auth/signin", user_handler.SignIn)
	api.Post("/auth/refresh", user_handler.RefreshToken)

	app.Listen(":8080")
}

func initDB() *sqlx.DB {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DATABASE_HOST"),
		os.Getenv("DATABASE_PORT"),
		os.Getenv("DATABASE_USER"),
		os.Getenv("DATABASE_PASSWORD"),
		os.Getenv("DATABASE_DB"),
		os.Getenv("DATABASE_SSLMODE"),
	)
	fmt.Println(dsn)
	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		panic(err)
	}
	return db
}
