package api

import (
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/jwt_tokens"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"log"

	"auth/internal/models"
	"auth/internal/utils"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strings"
)

type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GenerateTokensHandler генерация пары токенов (access и refresh) по GUID
// @Summary Генерация токенов для пользователя
// @Description Генерирует пару токенов (access и refresh) по ID пользователя
// @Tags Auth
// @Accept json
// @Produce json
// @Param user_id path string true "ID пользователя"
// @Success 200 {object} TokensResponse "Токены успешно сгенерированы"
// @Failure 400 {object} utils.ErrorResponse "Ошибка при создании токенов"
// @Failure 500 {object} utils.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/{user_id} [post]
func GenerateTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")

	_, err := uuid.Parse(userID)
	if err != nil {
		utils.SendError(w, http.StatusBadRequest, "неправильный user_id")
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	accessToken, refreshToken, err := jwt_tokens.GenerateAndSaveTokens(userID, ipAddress, userAgent)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed generate tokens")
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

// RefreshTokensHandler обновление пары токенов
// @Summary Обновление токенов для пользователя
// @Description Обновляет пару токенов (access и refresh) на основе переданных токенов.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body api.TokensResponse true "Тело запроса с токенами"
// @Success 200 {object} api.TokensResponse "Токены успешно обновлены"
// @Failure 400 {object} utils.ErrorResponse "Ошибка при обработке токенов"
// @Failure 401 {object} utils.ErrorResponse "Неавторизованный доступ или ошибка токена"
// @Failure 500 {object} utils.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/refresh [post]
func RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	var req TokensResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ip := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		ip = realIP
	} else if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	user := &models.UserAuthModel{
		IP:        ip,
		UserAgent: r.UserAgent(),
	}

	token, err := jwt.ParseWithClaims(req.AccessToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Cfg.JWTSecret), nil
	})
	if err != nil {
		utils.SendError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		utils.SendError(w, http.StatusUnauthorized, "invalid access token")
		return
	}
	jti, ok := claims["jti"].(string)
	if !ok {
		utils.SendError(w, http.StatusBadRequest, "invalid token")
		return
	}

	active, err := database.IsTokenActive(jti)
	if !ok {
		utils.SendError(w, http.StatusBadRequest, "invalid token")
		return
	}
	if !active {
		utils.SendError(w, http.StatusUnauthorized, "token not active")
		return
	}
	userID, storedIP, storedUserAgent, err := database.GetIPAndUserAgent(jti)
	if err != nil || err == pgx.ErrNoRows {
		utils.SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if storedUserAgent != user.UserAgent {
		err := database.DeactivateToken(jti)
		if err != nil {
			fmt.Printf("не удалоась деактивировать токен: " + err.Error())
		}
		utils.SendError(w, http.StatusUnauthorized, "user-agens changed")
		return
	}

	if storedIP != ip {
		go utils.SendAlertWebhook(userID, storedIP, ip)
	}

	newAccess, newRefresh, err := jwt_tokens.RefreshTokens(user, req.AccessToken, req.RefreshToken)
	if err != nil {
		utils.SendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := TokensResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed to encode JSON")
		return
	}

}

// GetUserIDHandler получение user_id из access токена
// @Summary Получение user_id из access токена
// @Description Извлекает user_id из контекста запроса, который был добавлен при проверке токена.
// @Tags Auth
// @Produce json
// @Success 200 {object} map[string]string "Возвращает user_id"
// @Failure 500 {object} utils.ErrorResponse "Ошибка сервера"
// @Router /auth/user-id [get]
func GetUserIDHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	if userID == nil {
		utils.SendError(w, http.StatusInternalServerError, "UserID not found")
		return
	}
	response := map[string]string{
		"user_guid": fmt.Sprintf("%v", userID),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed tp encode JSON")
	}

}

// LogoutHandler выход из системы (деактивация токена)
// @Summary Выход пользователя из системы
// @Description Деактивирует текущий токен (лог-аут) с помощью токена из заголовка Authorization.
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} map[string]string "Logout успешен"
// @Failure 400 {object} utils.ErrorResponse "Ошибка при извлечении токена"
// @Failure 401 {object} utils.ErrorResponse "Неавторизованный доступ или ошибка токена"
// @Failure 500 {object} utils.ErrorResponse "Ошибка сервера"
// @Router /auth/logout [post]
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		utils.SendError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Cfg.JWTSecret), nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		utils.SendError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Printf("Token invalid or claims extraction failed")
		utils.SendError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if err := claims.Valid(); err != nil {
		utils.SendError(w, http.StatusUnauthorized, "token validation failed")
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		utils.SendError(w, http.StatusBadRequest, "access_token_id not found")
		return
	}

	log.Printf("Extracted jti: %s", jti)

	if err := database.DeactivateToken(jti); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "failed logout: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"logout successful"}`))

}
