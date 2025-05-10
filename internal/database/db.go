package database

import (
	"auth/internal/config"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"time"
)

var Pool *pgxpool.Pool

func InitDB() error {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		config.Cfg.DBUser,
		config.Cfg.DBPassword,
		config.Cfg.DBHost,
		config.Cfg.DBPort,
		config.Cfg.DBName,
	)

	var err error
	Pool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		return err
	}

	if err = Pool.Ping(context.Background()); err != nil {
		return err
	}

	log.Println("Подключение к бд успешно")
	return nil

}

// CheckUserExists проверяет существует ли user_id в базе данных
func CheckUserExists(userID string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users_tokens WHERE user_id = $1)"
	err := Pool.QueryRow(context.Background(), query, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки пользователя: %v", err)
	}
	return exists, nil
}

func StoreRefreshToken(userID, tokenHash, ip, ua string) error {
	now := time.Now()

	expiresAt := now.Add(config.Cfg.RefreshTokenTTL)

	query := "INSERT INTO users_tokens (user_id, token_hash, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5)"
	_, err := Pool.Exec(context.Background(), query, userID, tokenHash, ip, ua, expiresAt)
	if err != nil {
		return fmt.Errorf("ошибка сохранения refresh токена: %v", err)
	}
	return nil
}
