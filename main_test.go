package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGenerateVerificationCode(t *testing.T) {
	code := generateVerificationCode()

	// OTP коды төрт таңбадан тұруы керек
	if len(code) != 4 {
		t.Errorf("Invalid OTP code length. Expected 4 digits, got: %d", len(code))
	}
}
func initTestDB() {
	var err error
	db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}

	// Тест үшін кестелерді жасау
	db.AutoMigrate(&User{}, &TempUser{})

	// Деректер базасын толығымен тазалау (барлық пайдаланушыларды өшіру)
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM temp_users")
}

func TestVerifyCode(t *testing.T) {
	initTestDB() // Тестке арналған SQLite базасын дайындау

	// Тіркелген пайдаланушыны жасау
	tempUser := TempUser{
		Name:             "Test User",
		Email:            "testuser@example.com",
		Password:         "testpassword",
		VerificationCode: "1234",
	}
	db.Create(&tempUser)

	// Верификация сұранысын жасау
	requestData := map[string]string{
		"email": "testuser@example.com",
		"code":  "1234",
	}

	body, _ := json.Marshal(requestData)
	request, _ := http.NewRequest("POST", "/verify-code", bytes.NewBuffer(body))
	response := httptest.NewRecorder()

	// Верификация функциясын шақыру
	verifyCode(response, request)

	// Тексеру: HTTP статус коды 200 болу керек
	if response.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got: %d", response.Code)
	}

	// Деректер базасында пайдаланушы бар ма, тексеру
	var user User
	err := db.Where("email = ?", "testuser@example.com").First(&user).Error
	if err != nil {
		t.Errorf("Verified user not found in the database")
	}
}

func TestJWTAuthentication(t *testing.T) {
    initTestDB() // Тест үшін дерекқорды тазалау

    // 🔹 Тестке арналған пайдаланушы жасау
    password := "securepassword123"
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    user := User{
        Name:     "JWT User",
        Email:    "jwtuser@example.com",
        Password: string(hashedPassword),
        Role:     "User",
        Verified: true,
    }
    db.Create(&user)

    // 🔹 Логин сұранысын жасау (OTP алу үшін)
    credentials := map[string]string{
        "email":    "jwtuser@example.com",
        "password": password,
    }

    body, _ := json.Marshal(credentials)
    request, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
    response := httptest.NewRecorder()

    // 🔹 Логин функциясын шақыру
    login(response, request)

    // 🔹 Деректер базасынан нақты OTP кодын алу
    var updatedUser User
    db.Where("email = ?", "jwtuser@example.com").First(&updatedUser)
    otp := updatedUser.OTP

    if otp == "" {
        t.Fatalf("OTP not found in database")
    }

    // 🔹 OTP-ді верификациялау
    otpData := map[string]string{
        "email": "jwtuser@example.com",
        "otp":   otp,
    }

    otpBody, _ := json.Marshal(otpData)
    otpRequest, _ := http.NewRequest("POST", "/verify-otp", bytes.NewBuffer(otpBody))
    otpResponse := httptest.NewRecorder()

    // 🔹 OTP функциясын тексеру
    verifyOTP(otpResponse, otpRequest)

    // 🔹 Тексеру: HTTP статус коды 200 болу керек
    if otpResponse.Code != http.StatusOK {
        t.Errorf("Expected status code 200, got: %d", otpResponse.Code)
    }

    // 🔹 Жауаптың ішінде JWT токен бар екенін тексеру
    var verifyResponse map[string]string
    json.NewDecoder(otpResponse.Body).Decode(&verifyResponse)

    token, exists := verifyResponse["token"]
    if !exists || token == "" {
        t.Errorf("JWT token not found in response")
    }

    // 🔹 Токенді валидациялау
    parsedToken, err := validateToken(token)
    if err != nil || !parsedToken.Valid {
        t.Errorf("Invalid JWT token")
    }
}
