package middleware

import (
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/utils"
	"context"
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
	"net/http"
	"strings"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			utils.SendError(w, http.StatusUnauthorized, "authorization header is mossong")
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		secretKey := config.Cfg.JWTSecret
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid signing method")
			}
			return []byte(secretKey), nil
		})

		if err != nil || !token.Valid {
			utils.SendError(w, http.StatusUnauthorized, "Invalid token")
			log.Println(token)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			utils.SendError(w, http.StatusUnauthorized, "Invalid token claims")
			return
		}

		userID := claims["user_id"]
		if userID == nil {
			utils.SendError(w, http.StatusUnauthorized, "not found user_id in token")
			return
		}

		jti, ok := claims["jti"].(string)
		if !ok {
			utils.SendError(w, http.StatusUnauthorized, "missing jti")
			return
		}

		active, err := database.IsTokenActive(jti)
		if !active {
			utils.SendError(w, http.StatusUnauthorized, " token not active")
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
