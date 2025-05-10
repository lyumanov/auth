package routes

import (
	"auth/internal/api"
	"github.com/go-chi/chi/v5"
)

func RegisterRout() *chi.Mux {
	r := chi.NewRouter()

	r.Post("/auth/{user_id}", api.GenerateTokensHandler)

	return r
}
