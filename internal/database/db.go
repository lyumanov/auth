package database

import (
	"auth/internal/config"
	"auth/internal/models"
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
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

func StoreRefreshToken(userID, tokenID, tokenHash, ip, ua string) error {
	now := time.Now()

	expiresAt := now.Add(config.Cfg.RefreshTokenTTL)

	query := "INSERT INTO users_tokens (user_id, token_id, token_hash, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)"
	_, err := Pool.Exec(context.Background(), query, userID, tokenID, tokenHash, ip, ua, expiresAt)
	if err != nil {
		return fmt.Errorf("ошибка сохранения refresh токена: %v", err)
	}
	return nil
}

func GetRefreshTokenByTokenID(tokenID string) (*models.UserAuthModel, error) {
	query := `
		SELECT id, user_id, token_id, token_hash, user_agent, ip_address, created_at, expires_at, active
		FROM users_tokens
		WHERE token_id = $1 AND active = true
	`

	row := Pool.QueryRow(context.Background(), query, tokenID)

	var uam models.UserAuthModel
	err := row.Scan(
		&uam.ID,
		&uam.UserID,
		&uam.TokenID,
		&uam.TokenHASH,
		&uam.UserAgent,
		&uam.IP,
		&uam.CreatedAt,
		&uam.ExpiresAt,
		&uam.Active,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &uam, nil
}

func DeactivateToken(jti string) error {
	query := `UPDATE users_tokens SET active = false WHERE token_id = $1`

	req, err := Pool.Exec(context.Background(), query, jti)
	if err != nil {
		return fmt.Errorf("failed to deactive refresh token: %v", err)
	}
	if req.RowsAffected() == 0 {
		return fmt.Errorf("token no found")
	}
	return nil
}

func GetIPAndUserAgent(jti string) (userID, ip, userAgent string, err error) {
	query := `
		SELECT user_id, ip_address, user_agent
		FROM users_tokens
		WHERE token_id = $1
	`

	err = Pool.QueryRow(context.Background(), query, jti).Scan(&userID, &ip, &userAgent)
	if err != nil {
		return "", "", "", err
	}
	return userID, ip, userAgent, nil
}

func IsTokenActive(jti string) (bool, error) {
	query := `SELECT active FROM users_tokens WHERE token_id = $1`
	row := Pool.QueryRow(context.Background(), query, jti)

	var active bool
	err := row.Scan(&active)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, nil
	}
	return active, nil
}
