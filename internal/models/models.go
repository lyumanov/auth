package models

import "time"

type UserAuthModel struct {
	ID        int
	UserID    string
	TokenID   string
	TokenHASH string
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool
}
