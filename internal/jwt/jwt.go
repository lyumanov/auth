package jwt

import (
	"auth/internal/config"
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

var jwtKey []byte

func GenerateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(config.Cfg.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	jwtKey = []byte(config.Cfg.JWTSecret)
	log.Println(jwtKey)

	accessToken, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func GenerateRefreshToken() (string, string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", "", err
	}

	hash, err := bcrypt.GenerateFromPassword(token, bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(hash), string(hash), nil

}
