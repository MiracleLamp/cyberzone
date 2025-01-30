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

	"github.com/golang-jwt/jwt/v4"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// **Құрылымдар**
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
	logFile *os.File
)
func writeLog(level, message string) {
	logrus.WithFields(logrus.Fields{"level": level}).Info(message)

	if logFile != nil {
		logFile.WriteString(fmt.Sprintf("%s [%s] %s\n", time.Now().Format(time.RFC3339), level, message))
	}
}

// **Базаға қосылу**
func initDatabase() {
	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
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

// **Тіркелу (Email верификациясымен)**
func signUpHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
		return
	}

	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
		return
	}

	verificationCode := fmt.Sprintf("%04d", rand.Intn(10000))
	tempUser := TempUser{Name: user.Name, Email: user.Email, Password: user.Password, VerificationCode: verificationCode}
	db.Create(&tempUser)

	go sendEmail(user.Email, "Verification Code", verificationCode)

	json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent"})
}

// **Email растау**
func verifyCode(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var tempUser TempUser
	if err := db.Where("email = ? AND verification_code = ?", requestData.Email, requestData.Code).First(&tempUser).Error; err != nil {
		http.Error(w, "Invalid verification code", http.StatusNotFound)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
	user := User{Name: tempUser.Name, Email: tempUser.Email, Password: string(hashedPassword), Role: "User", Verified: true}
	db.Create(&user)
	db.Delete(&tempUser)

	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified, you can login now."})
}

// **Логин (OTP жіберумен)**
func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		writeLog("error", fmt.Sprintf("Failed to decode JSON: %v", err))
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		writeLog("error", fmt.Sprintf("User not found for email: %s", credentials.Email))
		return
	}

	if !user.Verified {
		http.Error(w, `{"error":"Email is not verified"}`, http.StatusUnauthorized)
		writeLog("error", fmt.Sprintf("User email is not verified: %s", credentials.Email))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		writeLog("error", fmt.Sprintf("Invalid password for email: %s", credentials.Email))
		return
	}

	// Егер рөл жоқ болса, оны "User" деп орнату
	if user.Role == "" {
		user.Role = "User"
	}

	// JSON-ға рөлді қосу
	response := map[string]string{
		"message": "Login successful",
		"role":    user.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}


// **OTP Тексеру**
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

	token, _ := generateToken(user)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   token,
		"role":    user.Role,
	})
}

// **JWT Токен жасау**
func generateToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("your_secret_key"))
}

// **Email жіберу**
func sendEmail(to, subject, message string) {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	auth := smtp.PlainAuth("", "your-email@gmail.com", "your-email-password", smtpHost)

	msg := fmt.Sprintf("From: your-email@gmail.com\nTo: %s\nSubject: %s\n\n%s", to, subject, message)
	smtp.SendMail(smtpHost+":"+smtpPort, auth, "your-email@gmail.com", []string{to}, []byte(msg))
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

// **Server іске қосу**
func main() {
	initDatabase()
	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signUpHandler)
	mux.HandleFunc("/verify-code", verifyCode)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/verify-otp", verifyOTP)

	handler := rateLimitMiddleware(cors.Default().Handler(mux))
	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", handler)
}
