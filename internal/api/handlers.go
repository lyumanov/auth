package api

import (
	"auth/internal/database"
	"auth/internal/jwt"
	"auth/internal/utils"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
)

type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GenerateTokensHandler генерация пары токенов (access и refresh) по GUID
func GenerateTokensHandler(w http.ResponseWriter, r *http.Request) {
	userdID := chi.URLParam(r, "user_id")

	userExists, err := database.CheckUserExists(userdID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if userExists {
		utils.SendError(w, http.StatusBadRequest, "User is already authorized")
		return
	}

	accessToken, err := jwt.GenerateAccessToken(userdID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed generate access token")
		return
	}

	refreshToken, hash, err := jwt.GenerateRefreshToken()
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed generate refreshToken")
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	err = database.StoreRefreshToken(userdID, hash, ipAddress, userAgent)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "fialed store refreshtoken")
		return
	}

	tokensResponse := TokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(tokensResponse)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed encode tokens")
		return
	}
}
