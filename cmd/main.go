// @title Auth API
// @version 1.0
// @description Сервис аутентификации с JWT токенами.
// @host localhost:8000
// @BasePath /api
package main

import (
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/routes"

	"log"
	"net/http"
)

func main() {
	config.Load()

	if err := database.InitDB(); err != nil {
		log.Fatalf("Ошибка подключения к бд: %v", err)
	}
	defer database.Pool.Close()

	r := routes.RegisterRout()

	if err := http.ListenAndServe("0.0.0.0:"+config.Cfg.ServerPort, r); err == nil {
		log.Printf("\nСервер запущен. Порт: %s", config.Cfg.ServerPort)
	} else {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
