package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var mainTemplatePath = "index.html"

type messageResponse struct {
	ID         int64     `json:"id"`
	Ciphertext []byte    `json:"ciphertext"`
	IV         []byte    `json:"iv"`
	CreatedAt  time.Time `json:"created_at"`
}

func renderTemplate(w http.ResponseWriter, templatePath string, data any) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		http.Error(w, "Ошибка шаблона", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Ошибка отображения", http.StatusInternalServerError)
	}
}

func createHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	hours, err := strconv.Atoi(r.FormValue("expire"))
	if err != nil || hours <= 0 {
		http.Error(w, "неверное значение expire", http.StatusBadRequest)
		return
	}

	expireDate := time.Now().Add(time.Duration(hours) * time.Hour)

	roomIDBytes := make([]byte, 16)
	if _, err := rand.Read(roomIDBytes); err != nil {
		http.Error(w, "ошибка генерации ID комнаты", http.StatusInternalServerError)
		return
	}
	roomID := hex.EncodeToString(roomIDBytes)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, "ошибка генерации salt комнаты", http.StatusInternalServerError)
		return
	}

	_, err = pool.Exec(ctx,
		"INSERT INTO rooms1 (id, expire, salt) VALUES ($1, $2, $3)",
		roomID, expireDate, salt,
	)
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось создать комнату", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"room_id": roomID,
		"salt":    salt,
	}); err != nil {
		log.Print(err)
	}
	fmt.Printf("все ок, айди румы: %v", roomID)
}

func connectHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	roomID := strings.TrimSpace(r.FormValue("room_id"))
	if roomID == "" {
		http.Error(w, "room ID is required", http.StatusBadRequest)
		return
	}

	var salt []byte
	var encryptedRoomKey []byte
	var iv []byte

	err := pool.QueryRow(ctx,
		"SELECT salt, key, IV FROM rooms1 WHERE id = $1",
		roomID,
	).Scan(&salt, &encryptedRoomKey, &iv)
	if err != nil {
		log.Print(err)
		http.Error(w, "комната не найдена или ключ ещё не сохранён", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"room_key": encryptedRoomKey,
		"salt":     salt,
		"iv":       iv,
	}); err != nil {
		log.Print(err)
	}
}

func storeRoomKeyHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {

	roomID := strings.TrimSpace(r.FormValue("room_id"))
	roomKeyText := r.FormValue("room_key")
	ivText := r.FormValue("IV")
	if roomID == "" {
		http.Error(w, "room ID is required", http.StatusBadRequest)
		return
	}

	encryptedRoomKey, err := base64.StdEncoding.DecodeString(roomKeyText)
	if err != nil || len(encryptedRoomKey) == 0 {
		http.Error(w, "invalid room key", http.StatusBadRequest)
		return
	}
	iv, err := base64.StdEncoding.DecodeString(ivText)
	if err != nil || len(iv) == 0 {
		http.Error(w, "invalid IV", http.StatusBadRequest)
		return
	}

	result, err := pool.Exec(ctx,
		"UPDATE rooms1 SET key = $1, IV = $2 WHERE id = $3",
		encryptedRoomKey, iv, roomID,
	)
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось сохранить ключ комнаты", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "комната не найдена", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func messagesHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {
	if r.Method == http.MethodPost {
		storeMessage(w, r, pool, ctx)
		return
	}
	if r.Method == http.MethodGet {
		listMessages(w, r, pool, ctx)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func storeMessage(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	roomID := strings.TrimSpace(r.FormValue("room_id"))
	ciphertext, err := base64.StdEncoding.DecodeString(r.FormValue("ciphertext"))
	if err != nil || len(ciphertext) == 0 {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}
	iv, err := base64.StdEncoding.DecodeString(r.FormValue("iv"))
	if err != nil || len(iv) == 0 {
		http.Error(w, "invalid IV", http.StatusBadRequest)
		return
	}
	if roomID == "" {
		http.Error(w, "room ID is required", http.StatusBadRequest)
		return
	}

	var messageID int64
	var createdAt time.Time

	err = pool.QueryRow(ctx,
		"INSERT INTO messages (room_id, ciphertext, iv) VALUES ($1, $2, $3) RETURNING id, created_at",
		roomID, ciphertext, iv,
	).Scan(&messageID, &createdAt)
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось сохранить сообщение", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id":         messageID,
		"created_at": createdAt,
	}); err != nil {
		log.Print(err)
	}
}

func listMessages(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context) {

	roomID := strings.TrimSpace(r.URL.Query().Get("room_id"))
	if roomID == "" {
		http.Error(w, "room ID is required", http.StatusBadRequest)
		return
	}

	afterID := int64(0)
	if value := r.URL.Query().Get("after_id"); value != "" {
		parsedID, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsedID < 0 {
			http.Error(w, "invalid after_id", http.StatusBadRequest)
			return
		}
		afterID = parsedID
	}

	rows, err := pool.Query(ctx,
		"SELECT id, ciphertext, iv, created_at FROM messages WHERE room_id = $1 AND id > $2 ORDER BY id ASC LIMIT 100",
		roomID, afterID,
	)
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось получить сообщения", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := make([]messageResponse, 0)
	for rows.Next() {
		var message messageResponse
		if err := rows.Scan(&message.ID, &message.Ciphertext, &message.IV, &message.CreatedAt); err != nil {
			log.Print(err)
			http.Error(w, "не удалось прочитать сообщение", http.StatusInternalServerError)
			return
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		log.Print(err)
		http.Error(w, "не удалось прочитать сообщения", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(messages); err != nil {
		log.Print(err)
	}
}

func checker(pool *pgxpool.Pool, ctx context.Context) {

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		_, err := pool.Exec(ctx, "DELETE FROM rooms1 WHERE expire <= now()")
		if err != nil {
			log.Print(err)
		}
	}
}

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Print("DATABASE_URL не задан")
		return
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Print(err)
		return
	}
	defer pool.Close()

	go checker(pool, ctx)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			renderTemplate(w, mainTemplatePath, struct{ RoomID string }{})
			return
		}

		roomID := strings.Trim(r.URL.Path, "/")
		if roomID == "" || strings.Contains(roomID, "/") {
			http.NotFound(w, r)
			return
		}

		renderTemplate(w, mainTemplatePath, struct{ RoomID string }{RoomID: roomID})
	})

	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		storeRoomKeyHandler(w, r, pool, ctx)
	})
	http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		createHandler(w, r, pool, ctx)
	})
	http.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		connectHandler(w, r, pool, ctx)
	})
	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		messagesHandler(w, r, pool, ctx)
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Print(err)
	}
}
