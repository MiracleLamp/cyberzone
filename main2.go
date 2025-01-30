package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Определение структур данных
type User struct {
	ID        uint `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	Role      string
	Verified  bool `gorm:"default:false"`
	OTP       string
	OTPExpiry time.Time
}

type TempUser struct {
	ID               uint `gorm:"primaryKey"`
	Name             string
	Email            string `gorm:"unique"`
	Password         string
	VerificationCode string
}

var (
	db      *gorm.DB
	limiter = rate.NewLimiter(1, 3) // 1 запрос в секунду, с буфером на 3 запроса
	logFile *os.File
)

// Инициализация логирования
func initLogFile() {
	var err error
	logFile, err = os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
}

func writeLog(level, message string) {
	logrus.WithFields(logrus.Fields{"level": level}).Info(message)
	logFile.WriteString(fmt.Sprintf("%s [%s] %s\n", time.Now().Format(time.RFC3339), level, message))
}

// Инициализация базы данных
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
	db.AutoMigrate(&User{}, &TempUser{})
	writeLog("info", "Database initialized successfully")
}

// Middleware для ограничения частоты запросов
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

// Регистрация пользователя с отправкой верификационного кода
func signUpHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
		return
	}

	// Проверка существования email
	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
		return
	}

	verificationCode := fmt.Sprintf("%04d", rand.Intn(10000)) // 4-значный код
	tempUser := TempUser{Name: user.Name, Email: user.Email, Password: user.Password, VerificationCode: verificationCode}
	db.Create(&tempUser)

	// Отправка email
	go sendEmail("mirasbeyse@gmail.com", "fhqj slmp jexj vkrf", user.Email, "Verification Code", verificationCode)

	// Сәтті тіркелген хабарлама
	json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent"})
}

func verifyCode(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")

	if email == "" || code == "" {
		var requestData struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		email = requestData.Email
		code = requestData.Code
	}

	var tempUser TempUser
	if err := db.Where("email = ? AND verification_code = ?", email, code).First(&tempUser).Error; err != nil {
		http.Error(w, "Invalid verification code", http.StatusNotFound)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
	user := User{Name: tempUser.Name, Email: tempUser.Email, Password: string(hashedPassword), Role: "User", Verified: true}
	db.Create(&user)
	db.Delete(&tempUser)

	// Верификация сәтті аяқталды
	fmt.Fprintf(w, "Email successfully verified! You can now login.")
}

// Вход пользователя
func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Генерация и отправка OTP
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	user.OTP = otp
	user.OTPExpiry = time.Now().Add(5 * time.Minute)
	db.Save(&user)

	go sendEmail("mirasbeyse@gmail.com", "fhqj slmp jexj vkrfç", user.Email, "Your OTP Code", otp)

	json.NewEncoder(w).Encode(map[string]string{"message": "OTP sent"})
}

// Отправка email
func sendEmail(from, password, to, subject, message string) error {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	auth := smtp.PlainAuth("", from, password, smtpHost)

	logrus.WithFields(logrus.Fields{
		"from":    from,
		"to":      to,
		"subject": subject,
	}).Info("Sending email started")

	// HTML контенті үшін MIME типін анықтаймыз
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"utf-8\"\n\n"
	body := "<html><body>"
	body += "<h2>Welcome to our Service!</h2>"
	body += "<p>Click the link below to verify your email:</p>"
	// HTML батырмасы
	body += fmt.Sprintf(`
        <a href="http://localhost:8080/verify-code?email=%s&code=%s" style="
            display: inline-block;
            padding: 10px 20px;
            font-size: 16px;
            color: #fff;
            background-color: #28a745;
            text-decoration: none;
            border-radius: 5px;
        ">Verify Email</a>s
    `, to, message) // message-те верификациялық код болады
	body += "</body></html>"

	// Поштаны жібереміз
	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n" +
		mime + body

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"from":    from,
			"to":      to,
			"subject": subject,
			"error":   err.Error(),
		}).Error("Failed to send email")
		return err
	}

	logrus.WithFields(logrus.Fields{
		"from":    from,
		"to":      to,
		"subject": subject,
	}).Info("Email sent successfully")

	return nil
}

// Главная функция
func main() {
	initLogFile()
	initDatabase()

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signUpHandler)
	mux.HandleFunc("/verify-code", verifyCode)
	mux.HandleFunc("/login", login)

	handler := rateLimitMiddleware(cors.Default().Handler(mux))
	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", handler)
}
