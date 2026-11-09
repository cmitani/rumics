package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var mainTemplatePath = "index.html"

const sessionCookieName = "rumics_session"

type messageResponse struct {
	ID         int64     `json:"id"`
	Ciphertext []byte    `json:"ciphertext"`
	IV         []byte    `json:"iv"`
	CreatedAt  time.Time `json:"created_at"`
}

type session struct {
	roomID    string
	expiresAt time.Time
}

type sessionStore struct {
	mu     sync.Mutex
	tokens map[string]session
	ttl    time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{tokens: make(map[string]session), ttl: ttl}
}

func (s *sessionStore) create(roomID string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for value, sess := range s.tokens {
		if now.After(sess.expiresAt) {
			delete(s.tokens, value)
		}
	}
	s.tokens[token] = session{roomID: roomID, expiresAt: now.Add(s.ttl)}
	return token, nil
}

func (s *sessionStore) verify(token string, roomID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.tokens[token]
	if !ok || time.Now().After(sess.expiresAt) || sess.roomID != roomID {
		if ok {
			delete(s.tokens, token)
		}
		return false
	}
	return true
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func requireSession(r *http.Request, roomID string, sessions *sessionStore) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return sessions.verify(cookie.Value, roomID)
}

type hub struct {
	mu    sync.Mutex
	rooms map[string]map[*websocket.Conn]struct{}
}

func newHub() *hub {
	return &hub{rooms: make(map[string]map[*websocket.Conn]struct{})}
}

func (h *hub) subscribe(roomID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rooms[roomID] == nil {
		h.rooms[roomID] = make(map[*websocket.Conn]struct{})
	}
	h.rooms[roomID][conn] = struct{}{}
}

func (h *hub) unsubscribe(roomID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if room, ok := h.rooms[roomID]; ok {
		delete(room, conn)
		if len(room) == 0 {
			delete(h.rooms, roomID)
		}
	}
}

func (h *hub) broadcast(roomID string, payload []byte) {
	h.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(h.rooms[roomID]))
	for conn := range h.rooms[roomID] {
		conns = append(conns, conn)
	}
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, conn := range conns {
		if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
			h.unsubscribe(roomID, conn)
			conn.CloseNow()
		}
	}
}

func wsHandler(h *hub, sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roomID := strings.TrimSpace(r.URL.Query().Get("room_id"))
		if roomID == "" {
			http.Error(w, "room ID is required", http.StatusBadRequest)
			return
		}
		if !requireSession(r, roomID, sessions) {
			http.Error(w, "нет активной сессии для комнаты", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ctx = conn.CloseRead(ctx)

		h.subscribe(roomID, conn)
		defer h.unsubscribe(roomID, conn)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, 10*time.Second)
				pingErr := conn.Ping(pingCtx)
				pingCancel()
				if pingErr != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
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
	
	var idle_minutes *int
	if value := strings.TrimSpace(r.FormValue("idle_expire")); value != "" && value != "0" {
		idle_expire, err := strconv.Atoi(value)
		if err != nil || idle_expire < 0 {
			http.Error(w, "неверное значение idle_expire", http.StatusBadRequest)
			return
		}
		idle_expire *= 60 
		idle_minutes = &idle_expire
	}

	var max_messages *int
	if value := strings.TrimSpace(r.FormValue("max_messages")); value != "" && value != "0" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 0 {
			http.Error(w, "неверное значение max_messages", http.StatusBadRequest)
			return
		}
		max_messages = &limit
	}

	var max_users *int
	if value := strings.TrimSpace(r.FormValue("max_users")); value != "" && value != "0" {
		users, err := strconv.Atoi(value)
		if err != nil || users < 0 {
			http.Error(w, "неверное значение max_users", http.StatusBadRequest)
			return
		}
		max_users = &users
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
		"INSERT INTO rooms (id, expire, salt, idle_minutes, max_messages, max_users) VALUES ($1, $2, $3, $4, $5, $6)",
		roomID, expireDate, salt, idle_minutes, max_messages, max_users,
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
	var expire time.Time
	var idleMinutes *int
	var maxMessages *int
	var maxUsers *int
	var aliveCount int

	err := pool.QueryRow(ctx,
		"SELECT salt, key, IV, expire, idle_minutes, max_messages, max_users, "+
			"(SELECT count(*) FROM users WHERE users.room_id = rooms.id AND NOT dead) "+
			"FROM rooms WHERE id = $1",
		roomID,
	).Scan(&salt, &encryptedRoomKey, &iv, &expire, &idleMinutes, &maxMessages, &maxUsers, &aliveCount)
	if err != nil {
		log.Print(err)
		http.Error(w, "комната не найдена или ключ ещё не сохранён", http.StatusNotFound)
		return
	}
	if maxUsers != nil && aliveCount >= *maxUsers {
		http.Error(w, "комната заполнена", http.StatusForbidden)
		return
	}

	expireHours := math.Ceil(time.Until(expire).Hours())
	if expireHours < 0 {
		expireHours = 0
	}
	settings := map[string]any{"expire_hours": int(expireHours)}
	if idleMinutes != nil {
		settings["idle_hours"] = float64(*idleMinutes) / 60
	}
	if maxMessages != nil {
		settings["max_messages"] = *maxMessages
	}
	if maxUsers != nil {
		settings["max_users"] = *maxUsers
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"room_key": encryptedRoomKey,
		"salt":     salt,
		"iv":       iv,
		"settings": settings,
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
	keyHash, err := base64.StdEncoding.DecodeString(r.FormValue("key_hash"))
	if err != nil || len(keyHash) == 0 {
		http.Error(w, "invalid key hash", http.StatusBadRequest)
		return
	}

	result, err := pool.Exec(ctx,
		"UPDATE rooms SET key = $1, IV = $2, key_hash = $3 WHERE id = $4",
		encryptedRoomKey, iv, keyHash, roomID,
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

func authHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context, sessions *sessionStore) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	roomID := strings.TrimSpace(r.FormValue("room_id"))
	keyHash, err := base64.StdEncoding.DecodeString(r.FormValue("key_hash"))
	if roomID == "" || err != nil || len(keyHash) == 0 {
		http.Error(w, "room ID and key hash are required", http.StatusBadRequest)
		return
	}

	var storedHash []byte
	err = pool.QueryRow(ctx,
		"SELECT key_hash FROM rooms WHERE id = $1",
		roomID,
	).Scan(&storedHash)
	if err != nil {
		http.Error(w, "комната не найдена", http.StatusNotFound)
		return
	}
	if storedHash == nil || len(storedHash) != len(keyHash) ||
		subtle.ConstantTimeCompare(storedHash, keyHash) != 1 {
		http.Error(w, "неверный отпечаток ключа", http.StatusForbidden)
		return
	}

	token, err := sessions.create(roomID)
	if err != nil {
		http.Error(w, "не удалось создать сессию", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessions.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

type memberRow struct {
	UidHash []byte `json:"uid_hash"`
	Nick    string `json:"nick"`
	Dead    bool   `json:"dead"`
}

func listMembers(pool *pgxpool.Pool, ctx context.Context, roomID string) []memberRow {
	rows, err := pool.Query(ctx,
		"SELECT uid_hash, nick, dead FROM users WHERE room_id = $1 ORDER BY joined_at",
		roomID,
	)
	if err != nil {
		log.Print(err)
		return []memberRow{}
	}
	defer rows.Close()

	members := make([]memberRow, 0)
	for rows.Next() {
		var member memberRow
		if err := rows.Scan(&member.UidHash, &member.Nick, &member.Dead); err != nil {
			log.Print(err)
			return members
		}
		members = append(members, member)
	}
	return members
}

func broadcastPresence(pool *pgxpool.Pool, ctx context.Context, roomID string, h *hub) {
	payload, err := json.Marshal(map[string]any{
		"type":    "presence",
		"members": listMembers(pool, ctx, roomID),
	})
	if err == nil {
		h.broadcast(roomID, payload)
	}
}

func joinHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context, sessions *sessionStore, h *hub) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	roomID := strings.TrimSpace(r.FormValue("room_id"))
	uidHash, err := base64.StdEncoding.DecodeString(r.FormValue("uid_hash"))
	nick := strings.TrimSpace(r.FormValue("nick"))
	if roomID == "" || err != nil || len(uidHash) == 0 {
		http.Error(w, "room ID and uid hash are required", http.StatusBadRequest)
		return
	}
	if utf8.RuneCountInString(nick) > 32 {
		http.Error(w, "слишком длинный ник", http.StatusBadRequest)
		return
	}
	if !requireSession(r, roomID, sessions) {
		http.Error(w, "нет активной сессии для комнаты", http.StatusUnauthorized)
		return
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	var maxUsers *int
	err = tx.QueryRow(ctx,
		"SELECT max_users FROM rooms WHERE id = $1 FOR UPDATE",
		roomID,
	).Scan(&maxUsers)
	if err != nil {
		http.Error(w, "комната не найдена", http.StatusNotFound)
		return
	}

	var existingNick *string
	err = tx.QueryRow(ctx,
		"SELECT nick FROM users WHERE room_id = $1 AND uid_hash = $2",
		roomID, uidHash,
	).Scan(&existingNick)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Print(err)
		http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
		return
	}

	if existingNick == nil {
		var total int
		err = tx.QueryRow(ctx,
			"SELECT count(*) FROM users WHERE room_id = $1",
			roomID,
		).Scan(&total)
		if err != nil {
			log.Print(err)
			http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
			return
		}
		if maxUsers != nil {
			var alive int
			err = tx.QueryRow(ctx,
				"SELECT count(*) FROM users WHERE room_id = $1 AND NOT dead",
				roomID,
			).Scan(&alive)
			if err != nil {
				log.Print(err)
				http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
				return
			}
			if alive >= *maxUsers {
				http.Error(w, "комната заполнена", http.StatusForbidden)
				return
			}
		}
		if nick == "" {
			nick = fmt.Sprintf("user%d", total+1)
		}
		_, err = tx.Exec(ctx,
			"INSERT INTO users (room_id, uid_hash, nick) VALUES ($1, $2, $3)",
			roomID, uidHash, nick,
		)
	} else if nick == "" {
		nick = *existingNick
		_, err = tx.Exec(ctx,
			"UPDATE users SET last_seen = now(), dead = false WHERE room_id = $1 AND uid_hash = $2",
			roomID, uidHash,
		)
	} else {
		_, err = tx.Exec(ctx,
			"UPDATE users SET last_seen = now(), dead = false, nick = $3 WHERE room_id = $1 AND uid_hash = $2",
			roomID, uidHash, nick,
		)
	}
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		log.Print(err)
		http.Error(w, "не удалось подключиться к комнате", http.StatusInternalServerError)
		return
	}

	broadcastPresence(pool, ctx, roomID, h)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"nick":    nick,
		"members": listMembers(pool, ctx, roomID),
	}); err != nil {
		log.Print(err)
	}
}

func messagesHandler(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context, sessions *sessionStore, h *hub) {
	if r.Method == http.MethodPost {
		storeMessage(w, r, pool, ctx, sessions, h)
		return
	}
	if r.Method == http.MethodGet {
		listMessages(w, r, pool, ctx, sessions)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func storeMessage(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context, sessions *sessionStore, h *hub) {

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
	if !requireSession(r, roomID, sessions) {
		http.Error(w, "нет активной сессии для комнаты", http.StatusUnauthorized)
		return
	}
	const storeMessageQuery = `
		WITH bumped AS (
			UPDATE rooms
			SET message_count = message_count + 1,
			    last_activity = now()
			WHERE id = $1
			  AND expire > now()
			  AND (max_messages IS NULL OR message_count < max_messages)
			RETURNING 1
		)
		INSERT INTO messages (room_id, ciphertext, iv)
		SELECT $1, $2, $3 FROM bumped
		RETURNING id, created_at
	`

	var messageID int64
	var createdAt time.Time

	err = pool.QueryRow(ctx, storeMessageQuery, roomID, ciphertext, iv).Scan(&messageID, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "комната не найдена, истекла или лимит сообщений исчерпан", http.StatusForbidden)
		return
	}
	if err != nil {
		log.Print(err)
		http.Error(w, "не удалось сохранить сообщение", http.StatusInternalServerError)
		return
	}

	broadcastPayload, err := json.Marshal(map[string]any{
		"type":       "message",
		"id":         messageID,
		"ciphertext": ciphertext,
		"iv":         iv,
		"created_at": createdAt,
	})
	if err == nil {
		h.broadcast(roomID, broadcastPayload)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id":         messageID,
		"created_at": createdAt,
	}); err != nil {
		log.Print(err)
	}
}

func listMessages(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, ctx context.Context, sessions *sessionStore) {

	roomID := strings.TrimSpace(r.URL.Query().Get("room_id"))
	if roomID == "" {
		http.Error(w, "room ID is required", http.StatusBadRequest)
		return
	}
	if !requireSession(r, roomID, sessions) {
		http.Error(w, "нет активной сессии для комнаты", http.StatusUnauthorized)
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

func checker(pool *pgxpool.Pool, ctx context.Context, h *hub) {

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		_, err := pool.Exec(ctx, `
			DELETE FROM rooms
			WHERE expire <= now()
				OR (idle_minutes IS NOT NULL
					AND last_activity + idle_minutes * interval '1 minute' <= now())`)
		if err != nil {
			log.Print(err)
		}

		rows, err := pool.Query(ctx, `
			UPDATE users SET dead = true
			WHERE dead = false AND last_seen < now() - interval '10 minutes'
			RETURNING room_id`)
		if err != nil {
			log.Print(err)
			continue
		}
		touchedRooms := make(map[string]struct{})
		for rows.Next() {
			var roomID string
			if err := rows.Scan(&roomID); err != nil {
				log.Print(err)
				continue
			}
			touchedRooms[roomID] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			log.Print(err)
		}
		for roomID := range touchedRooms {
			broadcastPresence(pool, ctx, roomID, h)
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

	sessions := newSessionStore(12 * time.Hour)
	messageHub := newHub()

	go checker(pool, ctx, messageHub)

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
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authHandler(w, r, pool, ctx, sessions)
	})
	http.HandleFunc("/ws", wsHandler(messageHub, sessions))
	http.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		joinHandler(w, r, pool, ctx, sessions, messageHub)
	})
	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		messagesHandler(w, r, pool, ctx, sessions, messageHub)
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Print(err)
	}
}
