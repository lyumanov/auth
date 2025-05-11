package jwt_tokens

import (
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/models"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var jwtKey []byte

func GenerateAccessToken(userID string) (string, string, error) {
	tokenID := uuid.New()

	claims := jwt.MapClaims{
		"user_id": userID,
		"jti":     tokenID.String(),
		"exp":     time.Now().Add(config.Cfg.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	jwtKey = []byte(config.Cfg.JWTSecret)

	accessToken, err := token.SignedString(jwtKey)
	if err != nil {
		return "", "", err
	}

	return accessToken, tokenID.String(), nil
}

func GenerateRefreshToken() (string, string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", "", err
	}

	clientRefreshToken := base64.StdEncoding.EncodeToString(token)
	hash, err := bcrypt.GenerateFromPassword(token, bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return clientRefreshToken, string(hash), nil

}

func RefreshTokens(uam *models.UserAuthModel, accessToken, refreshToken string) (newAccess, newRefresh string, err error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signature method")
		}
		return []byte(config.Cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return "", "", fmt.Errorf("invalid access token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("invalid claims")
	}
	jti := claims["jti"].(string)

	decodedRefresh, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 refresh token")
	}

	record, err := database.GetRefreshTokenByTokenID(jti)
	if err != nil || record == nil || !record.Active {
		return "", "", fmt.Errorf("token not found or inactive")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(record.TokenHASH), decodedRefresh); err != nil {
		return "", "", fmt.Errorf("invalid refresh token")
	}

	_ = database.DeactivateToken(jti)

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("invalid token")
	}

	access, refresh, err := GenerateAndSaveTokens(userID, uam.IP, uam.UserAgent)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func GenerateAndSaveTokens(userID, ip, ua string) (string, string, error) {
	access, tokenID, err := GenerateAccessToken(userID)
	if err != nil {
		return "", "", err
	}
	refresh, hash, err := GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	err = database.StoreRefreshToken(userID, tokenID, hash, ip, ua)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil

}
