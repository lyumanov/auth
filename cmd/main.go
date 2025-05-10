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
	log.Println(config.Cfg.DBPassword)

	if err := database.InitDB(); err != nil {
		log.Fatalf("Ошибка подключения к бд: %v", err)
	}
	defer database.Pool.Close()

	r := routes.RegisterRout()

	if err := http.ListenAndServe(":"+config.Cfg.ServerPort, r); err == nil {
		log.Printf("\nСервер запущен. Порт: %s", config.Cfg.ServerPort)
	} else {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
