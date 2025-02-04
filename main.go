// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"strconv"
// 	"time"

// 	"github.com/rs/cors"
// 	"golang.org/x/time/rate"
// 	"gorm.io/driver/postgres"
// 	"gorm.io/gorm"
// 	"gorm.io/gorm/logger"
// 	"github.com/joho/godotenv"
// )

// type LogEntry struct {
// 	Level   string `json:"level"`
// 	Message string `json:"msg"`
// 	Time    string `json:"time"`
// }

// type User struct {
// 	ID        uint   `gorm:"primaryKey"`
// 	Name      string
// 	Email     string `gorm:"unique"`
// 	Password  string
// 	Role      string
// 	Verified  bool   `gorm:"default:false"` 
// }

// type TempUser struct {
// 	ID       uint   `gorm:"primaryKey"`
// 	Name     string
// 	Email    string `gorm:"unique"`
// 	Password string
	
// }

// var (
// 	db      *gorm.DB
// 	limiter = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests
// 	logFile *os.File
// )

// func initLogFile() {
// 	var err error
// 	logFile, err = os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Failed to open log file: %v", err)
// 	}
// 	log.SetOutput(logFile)
// }

// func init() {
//     err := godotenv.Load(".env")
//     if err != nil {
//         log.Fatalf("Error loading .env file: %v", err)
//     }
// }

// func writeLog(level, message string) {
// 	logEntry := LogEntry{
// 		Level:   level,
// 		Message: message,
// 		Time:    time.Now().Format("2006-01-02T15:04:05-0700"),
// 	}
// 	entry, _ := json.Marshal(logEntry)
// 	logFile.Write(entry)
// 	logFile.WriteString("\n")
// }

// func initDatabase() {
//     dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
//     var err error
//     db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
//         Logger: logger.Default.LogMode(logger.Silent),
//     })
//     if err != nil {
//         writeLog("error", "Failed to connect to database")
//         panic("Failed to connect to database")
//     }
//     db.AutoMigrate(&User{}, &TempUser{}) // Добавьте эту строку
//     writeLog("info", "Database initialized successfully")
// }

// func rateLimitMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if !limiter.Allow() {
// 			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
// 			writeLog("error", "Rate limit exceeded")
// 			return
// 		}
// 		next.ServeHTTP(w, r)
// 	})
// }

// func createUserHandler(w http.ResponseWriter, r *http.Request) {
// 	var user User
// 	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
// 		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
// 		writeLog("error", "Invalid input while creating user")
// 		return
// 	}

// 	if err := db.Create(&user).Error; err != nil {
// 		http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
// 		writeLog("error", "Failed to create user")
// 		return
// 	}

// 	w.WriteHeader(http.StatusCreated)
// 	json.NewEncoder(w).Encode(user)
// 	writeLog("info", fmt.Sprintf("User created: %v", user))
// }

// func getUserHandler(w http.ResponseWriter, r *http.Request) {
// 	id := r.URL.Query().Get("id")
// 	if id == "" {
// 		http.Error(w, `{"error":"missing id parameter"}`, http.StatusBadRequest)
// 		writeLog("error", "Missing id parameter in getUserHandler")
// 		return
// 	}

// 	var user User
// 	if err := db.First(&user, id).Error; err != nil {
// 		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
// 		writeLog("error", fmt.Sprintf("User not found: ID %s", id))
// 		return
// 	}

// 	json.NewEncoder(w).Encode(map[string]interface{}{"user": user})
// 	writeLog("info", fmt.Sprintf("User retrieved: %v", user))
// }

// func updateUserHandler(w http.ResponseWriter, r *http.Request) {
// 	var requestBody struct {
// 		ID    uint   `json:"id"`
// 		Name  string `json:"name"`
// 		Email string `json:"email"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
// 		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
// 		writeLog("error", "Invalid input while updating user")
// 		return
// 	}

// 	var user User
// 	if err := db.First(&user, requestBody.ID).Error; err != nil {
// 		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
// 		writeLog("error", fmt.Sprintf("User not found: ID %d", requestBody.ID))
// 		return
// 	}

// 	if requestBody.Name != "" {
// 		user.Name = requestBody.Name
// 	}
// 	if requestBody.Email != "" {
// 		user.Email = requestBody.Email
// 	}

// 	if err := db.Save(&user).Error; err != nil {
// 		http.Error(w, `{"error":"failed to update user"}`, http.StatusInternalServerError)
// 		writeLog("error", "Failed to update user")
// 		return
// 	}

// 	json.NewEncoder(w).Encode(map[string]interface{}{"message": "user updated successfully", "user": user})
// 	writeLog("info", fmt.Sprintf("User updated: %v", user))
// }

// func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
// 	var requestBody struct {
// 		ID uint `json:"id"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
// 		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
// 		writeLog("error", "Invalid input while deleting user")
// 		return
// 	}

// 	if err := db.Delete(&User{}, requestBody.ID).Error; err != nil {
// 		http.Error(w, `{"error":"failed to delete user"}`, http.StatusInternalServerError)
// 		writeLog("error", fmt.Sprintf("Failed to delete user: ID %d", requestBody.ID))
// 		return
// 	}

// 	json.NewEncoder(w).Encode(map[string]string{"message": "user deleted successfully"})
// 	writeLog("info", fmt.Sprintf("User deleted: ID %d", requestBody.ID))
// }

// func filterSortPaginateHandler(w http.ResponseWriter, r *http.Request) {
// 	filter := r.URL.Query().Get("filter")
// 	sort := r.URL.Query().Get("sort")
// 	page := r.URL.Query().Get("page")

// 	const limit = 10
// 	offset := 0
// 	if p, err := strconv.Atoi(page); err == nil && p > 1 {
// 		offset = (p - 1) * limit
// 	}

// 	allowedSortFields := map[string]bool{
// 		"name":  true,
// 		"email": true,
// 		"id":    true,
// 	}

// 	if sort != "" && !allowedSortFields[sort] {
// 		http.Error(w, `{"error":"invalid sort parameter"}`, http.StatusBadRequest)
// 		writeLog("error", "Invalid sort parameter")
// 		return
// 	}

// 	query := "SELECT id, name, email FROM users"
// 	if filter != "" {
// 		query += fmt.Sprintf(" WHERE name LIKE '%%%s%%'", filter)
// 	}
// 	if sort != "" {
// 		query += fmt.Sprintf(" ORDER BY %s", sort)
// 	}
// 	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

// 	writeLog("info", fmt.Sprintf("Executing query: %s", query))

// 	rows, err := db.Raw(query).Rows()
// 	if err != nil {
// 		http.Error(w, `{"error":"failed to fetch data"}`, http.StatusInternalServerError)
// 		writeLog("error", "Failed to fetch data")
// 		return
// 	}
// 	defer rows.Close()

// 	var users []User
// 	for rows.Next() {
// 		var user User
// 		if err := rows.Scan(&user.ID, &user.Name, &user.Email); err != nil {
// 			http.Error(w, `{"error":"failed to parse data"}`, http.StatusInternalServerError)
// 			writeLog("error", "Failed to parse data")
// 			return
// 		}
// 		users = append(users, user)
// 	}

// 	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
// 	writeLog("info", "Data retrieved successfully")
// }

// func main() {
//     initLogFile()
//     defer logFile.Close()

//     initDatabase()

//     mux := http.NewServeMux()

//     mux.HandleFunc("/add-user", createUserHandler)
//     mux.HandleFunc("/get-user", getUserHandler)
//     mux.HandleFunc("/update-user", updateUserHandler)
//     mux.HandleFunc("/delete-user", deleteUserHandler)
//     mux.HandleFunc("/filter-sort-paginate", filterSortPaginateHandler)
//     mux.HandleFunc("/signup", signUpHandler)
//     mux.HandleFunc("/login", login)
//     mux.HandleFunc("/verify-code", verifyCode) // Добавьте этот маршрут
//     mux.HandleFunc("/verify-otp", verifyOTP)   // Добавьте этот маршрут

//     c := cors.New(cors.Options{
//         AllowedOrigins: []string{"*"},
//         AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
//         AllowedHeaders: []string{"Content-Type", "Authorization"},
//     })

//     handler := rateLimitMiddleware(c.Handler(mux))
//     fmt.Println("server running on http://localhost:8080")
//     http.ListenAndServe(":8080", handler)
// }

// package main

// import (
//     "database/sql"
//     "encoding/json"
//     "fmt"
//     "net/http"
//     "net/smtp"
//     "time"

//     "github.com/gorilla/sessions"
//     "github.com/sirupsen/logrus"
//     "golang.org/x/crypto/bcrypt"
//     "golang.org/x/exp/rand"
//     "gorm.io/gorm"
// )

// var store = sessions.NewCookieStore([]byte("super-secret-key"))

// func signUpHandler(w http.ResponseWriter, r *http.Request) {
//     writeLog("info", "Received Sign Up request")

//     var user User
//     if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
//         writeLog("error", "Invalid input for Sign Up")
//         http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
//         return
//     }

//     // Validate input fields
//     if user.Name == "" || user.Email == "" || user.Password == "" || user.Role == "" {
//         writeLog("error", "Missing required fields in Sign Up")
//         http.Error(w, `{"error":"Missing required fields"}`, http.StatusBadRequest)
//         return
//     }

//     if user.Role != "User" && user.Role != "Admin" {
//         writeLog("error", "Invalid role in Sign Up")
//         http.Error(w, `{"error":"Invalid role"}`, http.StatusBadRequest)
//         return
//     }

//     // Check if email already exists
//     var existingUser User
//     err := db.Where("email = ?", user.Email).First(&existingUser).Error
//     if err == nil {
//         writeLog("error", "Email already exists during Sign Up")
//         http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
//         return
//     }
//     if err != gorm.ErrRecordNotFound {
//         writeLog("error", fmt.Sprintf("Error checking for existing user: %v", err))
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     // If user doesn't exist, create a new user in temp_users table
//     verificationCode := fmt.Sprintf("%04d", rand.Intn(10000)) // Generate verification code

//     tempUser := TempUser{
//         Name:             user.Name,
//         Email:            user.Email,
//         Password:         user.Password,
//         VerificationCode: verificationCode,
//     }

//     if err := db.Create(&tempUser).Error; err != nil {
//         writeLog("error", fmt.Sprintf("Error inserting temp user: %v", err))
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     writeLog("info", fmt.Sprintf("Temporary user created with ID: %d", tempUser.ID))

//     // Send the verification email
//     go func() {
//         subject := "Your Verification Code"
//         message := fmt.Sprintf("Here is your verification code: %s", verificationCode)
//         from := "nurbibirahmanberdy@gmail.com"
//         password := "vxaf gbyk lqqy zhyb"

//         err := sendEmail(from, password, user.Email, subject, message, "", "")
//         if err != nil {
//             writeLog("error", fmt.Sprintf("Failed to send verification email to %s: %v", user.Email, err))
//         } else {
//             writeLog("info", fmt.Sprintf("Verification code sent to %s: %s", user.Email, verificationCode))
//         }
//     }()

//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent to email"})
// }

// func verifyCode(w http.ResponseWriter, r *http.Request) {
//     writeLog("info", "Verification request received.")

//     if r.Method != http.MethodPost {
//         writeLog("error", fmt.Sprintf("Invalid request method: %s", r.Method))
//         http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
//         return
//     }

//     var requestData struct {
//         Email            string `json:"email"`
//         VerificationCode string `json:"code"`
//     }

//     err := json.NewDecoder(r.Body).Decode(&requestData)
//     if err != nil {
//         writeLog("error", fmt.Sprintf("Error decoding JSON: %v", err))
//         http.Error(w, "Invalid JSON", http.StatusBadRequest)
//         return
//     }

//     var tempUser TempUser
//     err = db.Where("email = ? AND verification_code = ?", requestData.Email, requestData.VerificationCode).First(&tempUser).Error
//     if err != nil {
//         writeLog("error", fmt.Sprintf("Error retrieving temp user: %v", err))
//         http.Error(w, "User not found or invalid verification code", http.StatusNotFound)
//         return
//     }

//     hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
//     if err != nil {
//         writeLog("error", fmt.Sprintf("Error hashing password: %v", err))
//         http.Error(w, "Internal server error", http.StatusInternalServerError)
//         return
//     }

//     user := User{
//         Name:     tempUser.Name,
//         Email:    tempUser.Email,
//         Password: string(hashedPassword),
//         Role:     "User",
//         Verified: true,
//     }

//     if err := db.Create(&user).Error; err != nil {
//         writeLog("error", fmt.Sprintf("Error inserting user into main table: %v", err))
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     if err := db.Delete(&tempUser).Error; err != nil {
//         writeLog("error", fmt.Sprintf("Error deleting temp user: %v", err))
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     writeLog("info", "User successfully verified and moved to main table")

//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(map[string]string{"message": "Email verified and user registered"})
// }

// func verifyOTP(w http.ResponseWriter, r *http.Request) {
//     var input struct {
//         Email string `json:"email"`
//         OTP   string `json:"otp"`
//     }

//     if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
//         http.Error(w, "Invalid request format", http.StatusBadRequest)
//         return
//     }

//     var storedOTP string
//     var otpExpiry time.Time
//     var userID int

//     err := db.QueryRow("SELECT id, otp, otp_expiry FROM users WHERE email = $1", input.Email).Scan(&userID, &storedOTP, &otpExpiry)
//     if err != nil {
//         if err == sql.ErrNoRows {
//             http.Error(w, "User not found", http.StatusNotFound)
//             return
//         }
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     if storedOTP != input.OTP || time.Now().After(otpExpiry) {
//         http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
//         return
//     }

//     _, err = db.Exec("UPDATE users SET otp = NULL, otp_expiry = NULL WHERE id = $1", userID)
//     if err != nil {
//         http.Error(w, "Failed to clear OTP", http.StatusInternalServerError)
//         return
//     }

//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(map[string]string{"message": "OTP verified"})
// }

// func sendEmail(from, password, to, subject, message, filename, fileContent string) error {
//     smtpHost := "smtp.gmail.com"
//     smtpPort := "587"

//     auth := smtp.PlainAuth("", from, password, smtpHost)

//     writeLog("info", fmt.Sprintf("Sending email started. From: %s, To: %s, Subject: %s", from, to, subject))

//     mime := "MIME-version: 1.0;\nContent-Type: multipart/mixed; boundary=\"boundary1\"\n\n"
//     body := "--boundary1\n"
//     body += "Content-Type: text/plain; charset=\"utf-8\"\n\n"
//     body += message + "\n\n"

//     if filename != "" && fileContent != "" {
//         body += "--boundary1\n"
//         body += "Content-Type: application/octet-stream; name=\"" + filename + "\"\n"
//         body += "Content-Disposition: attachment; filename=\"" + filename + "\"\n"
//         body += "Content-Transfer-Encoding: base64\n\n"
//         body += fileContent + "\n"
//     }

//     msg := "From: " + from + "\n" +
//         "To: " + to + "\n" +
//         "Subject: " + subject + "\n" +
//         mime + body + "--boundary1--"

//     err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
//     if err != nil {
//         writeLog("error", fmt.Sprintf("Failed to send email. From: %s, To: %s, Subject: %s, Error: %v", from, to, subject, err))
//         return err
//     }

//     writeLog("info", fmt.Sprintf("Email sent successfully. From: %s, To: %s, Subject: %s", from, to, subject))
//     return nil
// }

// func login(w http.ResponseWriter, r *http.Request) {
//     logrus.WithFields(logrus.Fields{
//         "method":   r.Method,
//         "endpoint": "/login",
//     }).Info("Request started")

//     if r.Method != http.MethodPost {
//         logrus.WithFields(logrus.Fields{
//             "method": r.Method,
//             "status": "fail",
//         }).Warn("Invalid request method")
//         http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
//         return
//     }

//     var credentials struct {
//         Email    string `json:"email"`
//         Password string `json:"password"`
//     }

//     err := json.NewDecoder(r.Body).Decode(&credentials)
//     if err != nil {
//         logrus.WithFields(logrus.Fields{
//             "error":  err.Error(),
//             "status": "fail",
//         }).Error("Failed to decode JSON")
//         w.Header().Set("Content-Type", "application/json")
//         w.WriteHeader(http.StatusBadRequest)
//         json.NewEncoder(w).Encode(map[string]string{
//             "message": "Invalid JSON format",
//             "status":  "fail",
//         })
//         return
//     }

//     var user User
//     var storedPassword string
//     query := `
//         SELECT id, name, email, password, role, verified 
//         FROM users 
//         WHERE email = $1`
//     err = db.QueryRow(query, credentials.Email).Scan(
//         &user.ID, &user.Name, &user.Email, &storedPassword, &user.Role, &user.Verified,
//     )
//     if err != nil {
//         if err == sql.ErrNoRows {
//             logrus.WithFields(logrus.Fields{
//                 "email":  credentials.Email,
//                 "status": "fail",
//             }).Warn("Invalid email or password")
//             w.Header().Set("Content-Type", "application/json")
//             w.WriteHeader(http.StatusUnauthorized)
//             json.NewEncoder(w).Encode(map[string]string{
//                 "message": "Invalid email or password",
//                 "status":  "fail",
//             })
//             return
//         }
//         logrus.WithFields(logrus.Fields{
//             "error":  err.Error(),
//             "status": "fail",
//         }).Error("Database error during login")
//         http.Error(w, "Database error", http.StatusInternalServerError)
//         return
//     }

//     err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(credentials.Password))
//     if err != nil {
//         logrus.WithFields(logrus.Fields{
//             "email":  credentials.Email,
//             "status": "fail",
//         }).Warn("Invalid email or password")
//         w.Header().Set("Content-Type", "application/json")
//         w.WriteHeader(http.StatusUnauthorized)
//         json.NewEncoder(w).Encode(map[string]string{
//             "message": "Invalid email or password",
//             "status":  "fail",
//         })
//         return
//     }

//     // Генерация OTP
//     otp := fmt.Sprintf("%06d", rand.Intn(1000000)) // 6-значный код
//     expiry := time.Now().Add(5 * time.Minute)      // Срок действия OTP: 5 минут

//     // Сохраняем OTP и время его действия в базе данных
//     _, err = db.Exec("UPDATE users SET otp = $1, otp_expiry = $2 WHERE id = $3", otp, expiry, user.ID)
//     if err != nil {
//         logrus.Error("Failed to save OTP:", err)
//         http.Error(w, "Internal server error", http.StatusInternalServerError)
//         return
//     }

//     // Отправка OTP на email
//     go sendEmail("nurbibirahmanberdy@gmail.com", "vxaf gbyk lqqy zhyb", user.Email, "Your OTP Code", fmt.Sprintf("Your OTP is: %s", otp), "", "")

//     //Cookies
//     session, _ := store.Get(r, "user-session")
//     session.Values["userID"] = user.ID
//     session.Values["name"] = user.Name
//     session.Values["email"] = user.Email
//     session.Values["role"] = user.Role
//     session.Values["verified"] = user.Verified
//     session.Save(r, w)

//     // Отправляем успешный ответ с данными пользователя (не с OTP)
//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(user)

//     logrus.WithFields(logrus.Fields{
//         "userID": user.ID,
//         "email":  user.Email,
//         "status": "success",
//     }).Info("User logged in successfully")
// }

// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"net/smtp"
// 	"os"
// 	"time"

// 	"github.com/golang-jwt/jwt/v4"
// 	"github.com/rs/cors"
// 	"github.com/sirupsen/logrus"

// 	"golang.org/x/crypto/bcrypt"
// 	"golang.org/x/exp/rand"
// 	"golang.org/x/time/rate"
// 	"gorm.io/driver/postgres"
// 	"gorm.io/gorm"
// 	"gorm.io/gorm/logger"
// )

// // Структуры
// type User struct {
// 	ID        uint   `gorm:"primaryKey"`
// 	Name      string
// 	Email     string `gorm:"unique"`
// 	Password  string
// 	Role      string
// 	Verified  bool      `gorm:"default:false"`
// 	OTP       string    `json:"otp,omitempty"`
// 	OTPExpiry time.Time `json:"otp_expiry,omitempty"`
// }

// type TempUser struct {
// 	ID               uint   `gorm:"primaryKey"`
// 	Name             string
// 	Email            string `gorm:"unique"`
// 	Password         string
// 	VerificationCode string
// }

// var (
// 	db      *gorm.DB
// 	limiter = rate.NewLimiter(1, 3)
// )

// // Логирование в файл JSON
// type LogEntry struct {
// 	Timestamp time.Time `json:"timestamp"`
// 	Level     string    `json:"level"`
// 	Message   string    `json:"message"`
// }

// func writeLogToFile(level, message string) {
// 	logEntry := LogEntry{
// 		Timestamp: time.Now(),
// 		Level:     level,
// 		Message:   message,
// 	}

// 	file, err := os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Error opening log file: %v", err)
// 	}
// 	defer file.Close()

// 	encoder := json.NewEncoder(file)
// 	encoder.SetIndent("", "  ")
// 	if err := encoder.Encode(logEntry); err != nil {
// 		log.Fatalf("Error writing log entry: %v", err)
// 	}
// }

// // Подключение к базе данных
// func initDatabase() {
// 	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
// 	var err error
// 	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
// 		Logger: logger.Default.LogMode(logger.Silent),
// 	})
// 	if err != nil {
// 		log.Fatal("Failed to connect to database:", err)
// 	}
// 	db.AutoMigrate(&User{}, &TempUser{})
// 	log.Println("Database initialized successfully")
// }


// // Регистрация с верификацией Email
// // Регистрация с уникальным кодом верификации
// // Регистрация с верификацией Email
// // Регистрация с верификацией Email
// // Регистрация с верификацией Email
// func signUpHandler(w http.ResponseWriter, r *http.Request) {
// 	var user User
// 	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Failed to decode user data: %v", err))
// 		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
// 		return
// 	}

// 	var existingUser User
// 	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
// 		writeLogToFile("error", fmt.Sprintf("Email already registered: %s", user.Email))
// 		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
// 		return
// 	}

// 	// Генерация уникального кода подтверждения
// 	verificationCode := generateVerificationCode()

// 	// Создаем временного пользователя в таблице temp_users
// 	tempUser := TempUser{
// 		Name:             user.Name,
// 		Email:            user.Email,
// 		Password:         user.Password,
// 		VerificationCode: verificationCode,
// 	}

// 	// Сохраняем временного пользователя в базу данных
// 	if err := db.Create(&tempUser).Error; err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Failed to create temp user in DB: %v", err))  // Добавляем подробный лог
// 		http.Error(w, `{"error":"Failed to create temporary user"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// Отправляем код подтверждения на email
// 	go sendEmail(user.Email, "Verification Code", verificationCode)

// 	writeLogToFile("info", fmt.Sprintf("Verification code sent to: %s", user.Email))

// 	// Ответ клиенту
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent"})
// }




// // Верификация email
// // Верификация email
// func verifyCode(w http.ResponseWriter, r *http.Request) {
// 	var requestData struct {
// 		Email string `json:"email"`
// 		Code  string `json:"code"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Invalid JSON format: %v", err))
// 		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
// 		return
// 	}

// 	var tempUser TempUser
// 	// Ищем временного пользователя по email и verification_code
// 	if err := db.Where("email = ? AND verification_code = ?", requestData.Email, requestData.Code).First(&tempUser).Error; err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Invalid verification code for email: %s", requestData.Email))
// 		http.Error(w, `{"error":"Invalid verification code"}`, http.StatusNotFound)
// 		return
// 	}

// 	// Хешируем пароль перед сохранением
// 	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
// 	user := User{
// 		Name:      tempUser.Name,
// 		Email:     tempUser.Email,
// 		Password:  string(hashedPassword),
// 		Role:      "User",
// 		Verified:  true,
// 	}

// 	// Создаем нового пользователя
// 	if err := db.Create(&user).Error; err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Failed to create verified user: %v", err))
// 		http.Error(w, `{"error":"Failed to create verified user"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// Удаляем временного пользователя
// 	if err := db.Delete(&tempUser).Error; err != nil {
// 		writeLogToFile("error", fmt.Sprintf("Failed to delete temp user: %v", err))
// 	}

// 	writeLogToFile("info", fmt.Sprintf("Email verified for: %s", requestData.Email))

// 	// Ответ клиенту
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified, you can login now."})
// }


// // Логин с OTP
// // Логин с OTP
// func login(w http.ResponseWriter, r *http.Request) {
// 	var credentials struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
// 		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
// 		return
// 	}

// 	var user User
// 	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
// 		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
// 		return
// 	}

// 	if !user.Verified {
// 		http.Error(w, `{"error":"Email is not verified"}`, http.StatusUnauthorized)
// 		return
// 	}

// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
// 		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
// 		return
// 	}

// 	// Генерация JWT токена
// 	token, err := generateToken(user)
// 	if err != nil {
// 		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
// 		return
// 	}

// 	writeLogToFile("info", fmt.Sprintf("Login successful for: %s", credentials.Email))

// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "Login successful",
// 		"token":   token,
// 		"role":    user.Role,
// 	})
//     // Генерация OTP для входа
// 	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
// 	user.OTP = otp
// 	user.OTPExpiry = time.Now().Add(5 * time.Minute)
// 	db.Save(&user)

// 	go sendEmail(user.Email, "Your OTP for login", otp)

// 	writeLogToFile("info", fmt.Sprintf("OTP sent to: %s", user.Email))

// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "OTP sent to your email.",
// 	})
// }

// // Генерация случайного кода
// func generateVerificationCode() string {
// 	rand.Seed(uint64(time.Now().UnixNano())) // Инициализация генератора случайных чисел
//     return fmt.Sprintf("%04d", rand.Intn(10000)) // Генерация кода из 4 цифр
// }

// // Проверка токена
// func validateToken(tokenString string) (*jwt.Token, error) {
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		// Проверка алгоритма подписи
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return []byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="), nil
// 	})
// 	return token, err
// }


// // Проверка OTP для входа
// func verifyOTP(w http.ResponseWriter, r *http.Request) {
// 	var input struct {
// 		Email string `json:"email"`
// 		OTP   string `json:"otp"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
// 		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
// 		return
// 	}

// 	var user User
// 	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
// 		http.Error(w, "User not found", http.StatusNotFound)
// 		return
// 	}

// 	if user.OTP != input.OTP || time.Now().After(user.OTPExpiry) {
// 		http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
// 		return
// 	}

// 	// Генерация JWT токена
// 	token, err := generateToken(user)
// 	if err != nil {
// 		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
// 		return
// 	}

// 	writeLogToFile("info", fmt.Sprintf("Login successful for: %s", input.Email))

// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "Login successful",
// 		"token":   token,
// 		"role":    user.Role,
// 	})
// }

// // Генерация JWT токена
// func generateToken(user User) (string, error) {
// 	claims := jwt.MapClaims{
// 		"email": user.Email,
// 		"role":  user.Role,
// 		"exp":   time.Now().Add(time.Hour * 24).Unix(),
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString([]byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="))
// }

// // Отправка Email
// func sendEmail(to, subject, message string) {
// 	smtpHost := "smtp.gmail.com"
// 	smtpPort := "587"
// 	auth := smtp.PlainAuth("", "mirasbeyse@gmail.com", "fhqj slmp jexj vkrf", smtpHost)

// 	msg := fmt.Sprintf("From: mirasbeyse@gmail.com\nTo: %s\nSubject: %s\n\n%s", to, subject, message)

// 	// Логирование перед отправкой письма
// 	log.Printf("Sending email to %s with subject %s", to, subject)

// 	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "mirasbeyse@gmail.com", []string{to}, []byte(msg))
// 	if err != nil {
// 		log.Printf("Error sending email: %v", err)
// 	} else {
// 		log.Printf("Email sent to %s", to)
// 	}
// }



// // Middleware для защиты
// func authMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// Получаем токен из заголовков
// 		tokenString := r.Header.Get("Authorization")
// 		if tokenString == "" {
// 			http.Error(w, "Missing token", http.StatusUnauthorized)
// 			return
// 		}

// 		// Удаляем "Bearer " из заголовка токена
// 		tokenString = tokenString[7:]

// 		token, err := validateToken(tokenString)
// 		if err != nil || !token.Valid {
// 			http.Error(w, "Invalid token", http.StatusUnauthorized)
// 			return
// 		}

// 		// Извлекаем роль из токена
// 		claims := token.Claims.(jwt.MapClaims)
// 		role := claims["role"].(string)

// 		// Пример ограничения доступа для определенной роли (например, только для администраторов)
// 		if role != "Admin" {
// 			http.Error(w, "Access denied", http.StatusForbidden)
// 			return
// 		}

// 		// Даем доступ к следующему хендлеру
// 		next.ServeHTTP(w, r)
// 	})
// }

// // Обработчик для админов
// func adminHandler(w http.ResponseWriter, r *http.Request) {
// 	// Логика для админов, например, доступ к панели управления.
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the Admin panel"})
// }

// // Обработчик для профиля пользователя
// func profileHandler(w http.ResponseWriter, r *http.Request) {
// 	// Логика для пользователя, например, доступ к личному кабинету.
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to your profile"})
// }

// // Главная функция, запуск сервера
// func main() {
// 	// Инициализация базы данных
// 	initDatabase()

// 	// Создание нового маршрутизатора
// 	mux := http.NewServeMux()

// 	// Обработчики для публичных маршрутов
// 	mux.HandleFunc("/signup", signUpHandler)        // Регистрация
// 	mux.HandleFunc("/verify-code", verifyCode)      // Верификация кода
// 	mux.HandleFunc("/login", login)                 // Логин
// 	mux.HandleFunc("/verify-otp", verifyOTP)        // Проверка OTP

// 	// Защищенные маршруты, требующие авторизации и проверки роли
// 	mux.Handle("/admin", authMiddleware(http.HandlerFunc(adminHandler))) // Административный интерфейс
// 	mux.Handle("/profile", authMiddleware(http.HandlerFunc(profileHandler))) // Профиль пользователя

// 	// Применяем rate limiting middleware и CORS
// 	handler := rateLimitMiddleware(cors.Default().Handler(mux))

// 	// Запуск сервера на порту 8080
// 	fmt.Println("Server running on http://localhost:8080")
// 	http.ListenAndServe(":8080", handler)
// }
package main 