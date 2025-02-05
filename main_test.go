package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tebeka/selenium"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "github.com/lib/pq"
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

func TestLoginWithOTP(t *testing.T) {
	const (
		chromeDriverPath = "/opt/homebrew/bin/chromedriver" // macOS (Homebrew арқылы орнатылған)

		// Selenium серверінің URL-і
		seleniumURL = "http://localhost:4444/wd/hub"

		// Сіздің сайттың негізгі беті
		baseURL = "http://127.0.0.1:5501/login.html"

		// Деректер базасының байланыс жолы
		dbConnString = "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
	)

	// 🔹 ChromeDriver қызметін іске қосу
	service, err := selenium.NewChromeDriverService(chromeDriverPath, 4444)
	if err != nil {
		t.Fatalf("Error starting ChromeDriver: %v", err)
	}
	defer service.Stop()

	// 🔹 WebDriver параметрлері
	caps := selenium.Capabilities{"browserName": "chrome"}
	wd, err := selenium.NewRemote(caps, seleniumURL)
	if err != nil {
		t.Fatalf("Error connecting to WebDriver: %v", err)
	}
	defer wd.Quit()

	// 🔹 Басты бетті жүктеу
	if err := wd.Get(baseURL); err != nil {
		t.Fatalf("Failed to load page: %v", err)
	}

	// 🔹 Логин батырмасын табу және басу
	loginLink, err := wd.FindElement(selenium.ByID, "loginButton")
	if err != nil {
		t.Fatalf("Login link not found: %v", err)
	}
	loginLink.Click()
	time.Sleep(2 * time.Second) // Модаль жүктелгенше күту

	// 🔹 Email енгізу
	email, err := wd.FindElement(selenium.ByID, "email")
	if err != nil {
		t.Fatalf("Email input not found: %v", err)
	}
	email.SendKeys("nurbibirahmanberdy@gmail.com")

	// 🔹 Құпия сөз енгізу
	password, err := wd.FindElement(selenium.ByID, "password")
	if err != nil {
		t.Fatalf("Password input not found: %v", err)
	}
	password.SendKeys("123")

	// 🔹 Логин батырмасын басу
	loginButton, err := wd.FindElement(selenium.ByID, "loginButton")
	if err != nil {
		t.Fatalf("Login button not found: %v", err)
	}
	loginButton.Click()

	time.Sleep(3 * time.Second) // OTP кодын генерациялау үшін күту

	// 🔹 Деректер базасынан OTP кодын алу
	db, err := sql.Open("postgres", dbConnString)
	if err != nil {
		t.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	var otp string
	query := "SELECT otp FROM users WHERE email = $1 AND otp IS NOT NULL"
	err = db.QueryRow(query, "nurbibirahmanberdy@gmail.com").Scan(&otp)
	if err != nil {
		t.Fatalf("Failed to fetch OTP: %v", err)
	}

	// WebDriver үшін күтуді анықтау
wd.SetImplicitWaitTimeout(10 * time.Second)

// OTP өрісін күту
otpInput, err := wd.FindElement(selenium.ByID, "otpinput")
if err != nil {
	t.Fatalf("OTP input field not found: %v", err)
}
otpInput.SendKeys(otp)

// OTP батырмасын күту
verifyButton, err := wd.FindElement(selenium.ByID, "otp")
if err != nil {
	t.Fatalf("Verify button not found: %v", err)
}
verifyButton.Click()

// Профиль сілтемесінің бар-жоғын күту
if _, err := wd.FindElement(selenium.ByLinkText, "Profile"); err != nil {
	t.Fatalf("Profile link not found after login: %v", err)
}

t.Log("Login successful with OTP!")


}
