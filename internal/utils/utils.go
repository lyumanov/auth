package utils

import (
	"auth/internal/config"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ErrorResponse представляет ошибку с кодом и сообщением.
// swagger:model
type ErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type AlertMsg struct {
	UserID    string `json:"user_id"`
	OldIP     string `json:"old_ip"`
	NewIP     string `json:"new_ip"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

func SendError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	errorResponse := ErrorResponse{}
	errorResponse.Error.Code = code
	errorResponse.Error.Message = message

	json.NewEncoder(w).Encode(errorResponse)

}

func SendAlertWebhook(userID, oldIP, newIP string) {
	msg := AlertMsg{
		UserID:    userID,
		OldIP:     oldIP,
		NewIP:     newIP,
		Message:   fmt.Sprintf("Попытка обновления токенов с нового IP: %s", newIP),
		Timestamp: time.Now().String(),
	}

	body, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("Ошибка json.Marshal", err)
		return
	}
	fmt.Println(config.Cfg.WebhookURL)
	req, err := http.NewRequest("POST", config.Cfg.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Ошибка создания запроса webhook", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Ошибка отправки webhook", err)
		return
	}
	defer resp.Body.Close()

}
