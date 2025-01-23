package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/cors"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type LogEntry struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Time    string `json:"time"`
}

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}


var (
	db      *gorm.DB
	limiter = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests
	logFile *os.File
)

func initLogFile() {
	var err error
	logFile, err = os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
}

func writeLog(level, message string) {
	logEntry := LogEntry{
		Level:   level,
		Message: message,
		Time:    time.Now().Format("2006-01-02T15:04:05-0700"),
	}
	entry, _ := json.Marshal(logEntry)
	logFile.Write(entry)
	logFile.WriteString("\n")
}

func initDatabase() {
	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		writeLog("error", "Failed to connect to database")
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{})
	writeLog("info", "Database initialized successfully")
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			writeLog("error", "Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
		writeLog("error", "Invalid input while creating user")
		return
	}

	if err := db.Create(&user).Error; err != nil {
		http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
		writeLog("error", "Failed to create user")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
	writeLog("info", fmt.Sprintf("User created: %v", user))
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"missing id parameter"}`, http.StatusBadRequest)
		writeLog("error", "Missing id parameter in getUserHandler")
		return
	}

	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		writeLog("error", fmt.Sprintf("User not found: ID %s", id))
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"user": user})
	writeLog("info", fmt.Sprintf("User retrieved: %v", user))
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		ID    uint   `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
		writeLog("error", "Invalid input while updating user")
		return
	}

	var user User
	if err := db.First(&user, requestBody.ID).Error; err != nil {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		writeLog("error", fmt.Sprintf("User not found: ID %d", requestBody.ID))
		return
	}

	if requestBody.Name != "" {
		user.Name = requestBody.Name
	}
	if requestBody.Email != "" {
		user.Email = requestBody.Email
	}

	if err := db.Save(&user).Error; err != nil {
		http.Error(w, `{"error":"failed to update user"}`, http.StatusInternalServerError)
		writeLog("error", "Failed to update user")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"message": "user updated successfully", "user": user})
	writeLog("info", fmt.Sprintf("User updated: %v", user))
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		ID uint `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
		writeLog("error", "Invalid input while deleting user")
		return
	}

	if err := db.Delete(&User{}, requestBody.ID).Error; err != nil {
		http.Error(w, `{"error":"failed to delete user"}`, http.StatusInternalServerError)
		writeLog("error", fmt.Sprintf("Failed to delete user: ID %d", requestBody.ID))
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "user deleted successfully"})
	writeLog("info", fmt.Sprintf("User deleted: ID %d", requestBody.ID))
}

func filterSortPaginateHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sort := r.URL.Query().Get("sort")
	page := r.URL.Query().Get("page")

	const limit = 10
	offset := 0
	if p, err := strconv.Atoi(page); err == nil && p > 1 {
		offset = (p - 1) * limit
	}

	allowedSortFields := map[string]bool{
		"name":  true,
		"email": true,
		"id":    true,
	}

	if sort != "" && !allowedSortFields[sort] {
		http.Error(w, `{"error":"invalid sort parameter"}`, http.StatusBadRequest)
		writeLog("error", "Invalid sort parameter")
		return
	}

	query := "SELECT id, name, email FROM users"
	if filter != "" {
		query += fmt.Sprintf(" WHERE name LIKE '%%%s%%'", filter)
	}
	if sort != "" {
		query += fmt.Sprintf(" ORDER BY %s", sort)
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	writeLog("info", fmt.Sprintf("Executing query: %s", query))

	rows, err := db.Raw(query).Rows()
	if err != nil {
		http.Error(w, `{"error":"failed to fetch data"}`, http.StatusInternalServerError)
		writeLog("error", "Failed to fetch data")
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email); err != nil {
			http.Error(w, `{"error":"failed to parse data"}`, http.StatusInternalServerError)
			writeLog("error", "Failed to parse data")
			return
		}
		users = append(users, user)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
	writeLog("info", "Data retrieved successfully")
}

func main() {
	initLogFile()
	defer logFile.Close()

	initDatabase()

	mux := http.NewServeMux()

	mux.HandleFunc("/add-user", createUserHandler)
	mux.HandleFunc("/get-user", getUserHandler)
	mux.HandleFunc("/update-user", updateUserHandler)
	mux.HandleFunc("/delete-user", deleteUserHandler)
	mux.HandleFunc("/filter-sort-paginate", filterSortPaginateHandler)
	mux.HandleFunc("/signup", signUpHandler)
	mux.HandleFunc("/login", loginHandler)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	handler := rateLimitMiddleware(c.Handler(mux))
	fmt.Println("server running on http://localhost:8080")
	http.ListenAndServe(":8080", handler)
}
