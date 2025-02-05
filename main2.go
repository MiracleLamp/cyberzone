package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Структуры
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	Role      string
	Verified  bool      `gorm:"default:false"`
	OTP       string    `json:"otp,omitempty"`
	OTPExpiry time.Time `json:"otp_expiry,omitempty"`
}

type TempUser struct {
	ID               uint   `gorm:"primaryKey"`
	Name             string
	Email            string `gorm:"unique"`
	Password         string
	VerificationCode string
}

var (
	db      *gorm.DB
	limiter = rate.NewLimiter(1, 3)
)

// Логирование в файл JSON
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

func writeLogToFile(level, message string) {
	logEntry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	file, err := os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(logEntry); err != nil {
		log.Fatalf("Error writing log entry: %v", err)
	}
}

// Подключение к базе данных
func initDatabase() {
	dsn := "postgresql://database_awk3_user:IYA0ZWH9esDfERi5J4uwOdNEWMy8Q5Sh@dpg-cuhmm01u0jms73ac6e3g-a.oregon-postgres.render.com/database_awk3"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	db.AutoMigrate(&User{}, &TempUser{})
	log.Println("Database initialized successfully")
}
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			logrus.Error("Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
// Генерация случайного кода
func generateVerificationCode() string {
	rand.Seed(uint64(time.Now().UnixNano())) // Инициализация генератора случайных чисел
	return fmt.Sprintf("%04d", rand.Intn(10000)) // Генерация кода из 4 цифр
}

// Отправка Email
func sendEmail(to, subject, message string) {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	auth := smtp.PlainAuth("", "mirasbeyse@gmail.com", "fhqj slmp jexj vkrf", smtpHost)

	msg := fmt.Sprintf("From: mirasbeyse@gmail.com\nTo: %s\nSubject: %s\n\n%s", to, subject, message)

	// Логирование перед отправкой письма
	log.Printf("Sending email to %s with subject %s", to, subject)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "mirasbeyse@gmail.com", []string{to}, []byte(msg))
	if err != nil {
		log.Printf("Error sending email: %v", err)
	} else {
		log.Printf("Email sent to %s", to)
	}
}

// Регистрация с верификацией Email
func signUpHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to decode user data: %v", err))
		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
		return
	}

	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		writeLogToFile("error", fmt.Sprintf("Email already registered: %s", user.Email))
		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
		return
	}

	// Генерация уникального кода подтверждения
	verificationCode := generateVerificationCode()

	// Создаем временного пользователя в таблице temp_users
	tempUser := TempUser{
		Name:             user.Name,
		Email:            user.Email,
		Password:         user.Password,
		VerificationCode: verificationCode,
	}

	// Сохраняем временного пользователя в базу данных
	if err := db.Create(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to create temp user in DB: %v", err))
		http.Error(w, `{"error":"Failed to create temporary user"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем код подтверждения на email
	go sendEmail(user.Email, "Verification Code", verificationCode)

	writeLogToFile("info", fmt.Sprintf("Verification code sent to: %s", user.Email))

	// Ответ клиенту
	json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent"})
}

// Верификация email
func verifyCode(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		writeLogToFile("error", fmt.Sprintf("Invalid JSON format: %v", err))
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	var tempUser TempUser
	// Ищем временного пользователя по email и verification_code
	if err := db.Where("email = ? AND verification_code = ?", requestData.Email, requestData.Code).First(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Invalid verification code for email: %s", requestData.Email))
		http.Error(w, `{"error":"Invalid verification code"}`, http.StatusNotFound)
		return
	}

	// Хешируем пароль перед сохранением
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
	user := User{
		Name:      tempUser.Name,
		Email:     tempUser.Email,
		Password:  string(hashedPassword),
		Role:      "User",
		Verified:  true,
	}

	// Создаем нового пользователя
	if err := db.Create(&user).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to create verified user: %v", err))
		http.Error(w, `{"error":"Failed to create verified user"}`, http.StatusInternalServerError)
		return
	}

	// Удаляем временного пользователя
	if err := db.Delete(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to delete temp user: %v", err))
	}

	writeLogToFile("info", fmt.Sprintf("Email verified for: %s", requestData.Email))

	// Ответ клиенту
	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified, you can login now."})
}

// Логин с OTP
func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	if !user.Verified {
		http.Error(w, `{"error":"Email is not verified"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// Генерация OTP для входа
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	user.OTP = otp
	user.OTPExpiry = time.Now().Add(5 * time.Minute)
	db.Save(&user)

	go sendEmail(user.Email, "Your OTP for login", otp)

	writeLogToFile("info", fmt.Sprintf("OTP sent to: %s", user.Email))

	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP sent to your email.",
	})
}

// Проверка OTP для входа
func verifyOTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.OTP != input.OTP || time.Now().After(user.OTPExpiry) {
		http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
		return
	}

	// Генерация JWT токена
	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	writeLogToFile("info", fmt.Sprintf("Login successful for: %s", input.Email))

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   token,
		"role":    user.Role,
	})
}

// Генерация JWT токена
func generateToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="))
}

// Проверка токена
func validateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="), nil
	})
	return token, err
}

// Middleware для защиты
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовков
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Удаляем "Bearer " из заголовка токена
		tokenString = tokenString[7:]

		token, err := validateToken(tokenString)
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Извлекаем роль из токена
		claims := token.Claims.(jwt.MapClaims)
		role := claims["role"].(string)

		// Пример ограничения доступа для определенной роли (например, только для администраторов)
		if role != "Admin" {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Даем доступ к следующему хендлеру
		next.ServeHTTP(w, r)
	})
}

// Обработчик для админов
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// Логика для админов, например, доступ к панели управления.
	json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the Admin panel"})
}

// Главная функция, запуск сервера
func main() {
	initDatabase()
	mux := http.NewServeMux()

	// Обработчики для публичных маршрутов
	mux.HandleFunc("/signup", signUpHandler)
	mux.HandleFunc("/verify-code", verifyCode)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/verify-otp", verifyOTP)

	// Защищенные маршруты, требующие авторизации и проверки роли
	mux.Handle("/admin", authMiddleware(http.HandlerFunc(adminHandler))) // Административный интерфейс

	// Применяем rate limiting middleware и CORS
	handler := rateLimitMiddleware(cors.Default().Handler(mux))

	// Запуск сервера на порту 8080
	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", handler)
}
