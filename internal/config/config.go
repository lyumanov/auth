package config

import (
	"log"
	"os"
	"time"
)

type Config struct {
	ServerPort      string
	DBHost          string
	DBPort          string
	DBUser          string
	DBPassword      string
	DBName          string
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	WebhookURL      string
}

var Cfg *Config

func Load() {
	Cfg = &Config{
		ServerPort:      getEnv("SERVER_PORT", "8080"),
		DBHost:          getEnv("DB_HOST", "localhost"),
		DBPort:          getEnv("DB_PORT", "5432"),
		DBUser:          getEnv("DB_USER", "postgres"),
		DBPassword:      getEnv("DB_PASSWORD", "postgres"),
		DBName:          getEnv("DB_NAME", "auth_db"),
		JWTSecret:       getEnv("JWT_SECRET", "jwtsecretkey"),
		AccessTokenTTL:  parseDuration("ACCESS_TOKEN_TTL", "15m"),
		RefreshTokenTTL: parseDuration("REFRESH_TOKEN_TTL", "24h"),
		WebhookURL:      getEnv("WEBHOOK_URL", "http://localhost:8000/webhook"),
	}
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func parseDuration(key, defaultValue string) time.Duration {
	val := getEnv(key, defaultValue)
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed parse duration: %s %v", val, err)
	}
	return d
}
