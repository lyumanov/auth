package routes

import (
	_ "auth/docs"
	"auth/internal/api"
	"auth/internal/middleware"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

func RegisterRout() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Post("/api/auth/{user_id}", api.GenerateTokensHandler)
	r.Post("/api/auth/refresh", api.RefreshTokensHandler)

	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware)

		r.Get("/api/auth/get_id", api.GetUserIDHandler)
		r.Post("/api/auth/logout", api.LogoutHandler)
	})

	return r
}
