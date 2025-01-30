package main

import (
	"database/sql"
	"strconv" // Импортируем пакет для конвертации типов
	"testing"

	"github.com/tebeka/selenium"
	
)


var testDB *sql.DB



func setupTestDB() (*sql.DB, error) {
    db, err := sql.Open("postgres", "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable")
    if err != nil {
        return nil, err
    }
    return db, nil
}




func TestAdminLogin(t *testing.T) {
	const (
		seleniumPath    = "/Users/nurbibirahmanberdieva/Downloads/selenium-server-standalone.jar" // Укажите путь к selenium-server-standalone.jar
		geckoDriverPath = "/usr/local/bin/chromedriver"                   // Путь к chromedriver
		port            = 8080
	)

	// Проверка, инициализирована ли база данных
	if db == nil {
		t.Fatal("Database connection is not initialized")
	}

	
	// Настройка и запуск Selenium сервер и драйвера
	opts := []selenium.ServiceOption{}
	service, err := selenium.NewChromeDriverService(geckoDriverPath, port, opts...)
	if err != nil {
		t.Fatalf("Error starting the ChromeDriver server: %v", err)
	}
	defer service.Stop()

	// Запуск WebDriver
	caps := selenium.Capabilities{"browserName": "chrome"}
	wd, err := selenium.NewRemote(caps, "http://localhost:"+strconv.Itoa(port)) // Преобразуем int в строку
	if err != nil {
		t.Fatalf("Error connecting to WebDriver: %v", err)
	}
	defer wd.Quit()

	// Переход на страницу входа
	wd.Get("http://localhost:8080/admin")
	usernameInput, _ := wd.FindElement(selenium.ByID, "username")
	passwordInput, _ := wd.FindElement(selenium.ByID, "password")
	loginButton, _ := wd.FindElement(selenium.ByID, "login")

	// Ввод данных для входа
	usernameInput.SendKeys("admin")
	passwordInput.SendKeys("securepassword")
	loginButton.Click()

	// Проверка, что после входа появляется "Admin Dashboard"
	dashboardHeader, err := wd.FindElement(selenium.ByTagName, "h1")
	if err != nil {
		t.Fatalf("Could not find dashboard header: %v", err)
	}
	headerText, _ := dashboardHeader.Text()
	if headerText != "Admin Dashboard" {
		t.Errorf("Expected 'Admin Dashboard', got '%s'", headerText)
	}
}
