package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB
var log = logrus.New()
var limiter = rate.NewLimiter(3, 5) // Лимит: 3 сұраныс/секунд, 5 қатарынан рұқсат етіледі

type User struct {
	ID    uint   `json:"id" gorm:"primaryKey"`
	Name  string `json:"name"`
	Email string `json:"email" gorm:"unique"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Users   []User `json:"users,omitempty"`
	User    *User  `json:"user,omitempty"`
}

// Rate Limiting Middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			log.WithFields(logrus.Fields{
				"action":  "rateLimit",
				"status":  "failed",
				"message": "Rate limit exceeded",
			}).Warn("Too many requests")
			return
		}
		next(w, r)
	}
}

// Initialize the database connection
func initDatabase() {
	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
	var err error

	// Open connection to PostgreSQL
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "initDatabase",
			"error":  err.Error(),
		}).Fatal("Failed to connect to PostgreSQL server")
	}

	// Auto migrate the User model
	db.AutoMigrate(&User{})
	log.WithField("action", "initDatabase").Info("Database initialized successfully")
}

// Add a new user to the database
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.Name == "" || user.Email == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "addUser",
			"status": "failed",
			"error":  "Invalid input",
		}).Error("Failed to decode request body")
		return
	}

	// Add the user to the database
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		log.WithFields(logrus.Fields{
			"action": "addUser",
			"status": "failed",
			"error":  result.Error.Error(),
		}).Error("Failed to add user to database")
		return
	}

	log.WithFields(logrus.Fields{
		"action": "addUser",
		"status": "success",
		"userID": user.ID,
	}).Info("User added successfully")

	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User added successfully", User: &user})
}

// Delete a user by ID
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "deleteUser",
			"status": "failed",
			"error":  "Invalid input",
		}).Error("Failed to decode request body")
		return
	}
	id, err := strconv.Atoi(data["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "deleteUser",
			"status": "failed",
			"error":  "Invalid user ID",
		}).Error("Failed to parse user ID")
		return
	}
	result := db.Delete(&User{}, id)
	if result.Error != nil || result.RowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		log.WithFields(logrus.Fields{
			"action": "deleteUser",
			"status": "failed",
			"userID": id,
		}).Error("Failed to delete user")
		return
	}

	log.WithFields(logrus.Fields{
		"action": "deleteUser",
		"status": "success",
		"userID": id,
	}).Info("User deleted successfully")

	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User deleted successfully"})
}

// Update an existing user
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "updateUser",
			"status": "failed",
			"error":  "Invalid JSON format",
		}).Error("Failed to decode request body")
		return
	}

	// Check that all required fields are present
	if user.ID == 0 || user.Name == "" || user.Email == "" {
		http.Error(w, "Missing required fields: ID, Name, or Email", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "updateUser",
			"status": "failed",
			"error":  "Missing fields",
		}).Error("User update failed due to missing fields")
		return
	}

	// Update user data in the database
	result := db.Model(&User{}).Where("id = ?", user.ID).Updates(User{Name: user.Name, Email: user.Email})
	if result.Error != nil || result.RowsAffected == 0 {
		http.Error(w, "User not found or update failed", http.StatusNotFound)
		log.WithFields(logrus.Fields{
			"action": "updateUser",
			"status": "failed",
			"userID": user.ID,
			"error":  "User not found or no rows affected",
		}).Error("Failed to update user")
		return
	}

	log.WithFields(logrus.Fields{
		"action": "updateUser",
		"status": "success",
		"userID": user.ID,
	}).Info("User updated successfully")

	// Send success response
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User updated successfully"})
}

// Get a user by ID
func getUserByIDHandler(w http.ResponseWriter, r *http.Request) {
	// Get the "id" parameter from the URL query
	idParam := r.URL.Query().Get("id")
	if idParam == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "getUserByID",
			"status": "failed",
			"error":  "Missing ID parameter",
		}).Error("Failed to fetch user due to missing ID parameter")
		return
	}

	// Convert the ID to an integer
	id, err := strconv.Atoi(idParam)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"action": "getUserByID",
			"status": "failed",
			"error":  "Invalid ID format",
		}).Error("Failed to fetch user due to invalid ID format")
		return
	}

	// Fetch the user from the database
	var user User
	result := db.First(&user, id)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		log.WithFields(logrus.Fields{
			"action": "getUserByID",
			"status": "failed",
			"userID": id,
			"error":  result.Error.Error(),
		}).Error("Failed to fetch user")
		return
	}

	// Return the user as a response
	log.WithFields(logrus.Fields{
		"action": "getUserByID",
		"status": "success",
		"userID": id,
	}).Info("User fetched successfully")

	json.NewEncoder(w).Encode(Response{Status: "success", User: &user})
}

// Fetch all users with Filtering, Sorting, and Pagination
func FST(w http.ResponseWriter, r *http.Request) {
	var users []User

	// Retrieve query parameters
	filter := r.URL.Query().Get("filter") // Filtering
	sort := r.URL.Query().Get("sort")     // Sorting
	page := r.URL.Query().Get("page")     // Pagination

	// Default pagination values
	limit := 2 // Number of users per page
	offset := 0

	// Calculate offset for pagination
	if p, err := strconv.Atoi(page); err == nil && p > 1 {
		offset = (p - 1) * limit
	}

	// Build query with filtering, sorting, and pagination
	query := db
	if filter != "" {
		query = query.Where("name LIKE ?", "%"+filter+"%")
		log.WithFields(logrus.Fields{
			"action": "filterUsers",
			"filter": filter,
		}).Info("Filtering users")
	}
	if sort != "" {
		query = query.Order(sort)
		log.WithFields(logrus.Fields{
			"action": "sortUsers",
			"sort":   sort,
		}).Info("Sorting users")
	}

	result := query.Limit(limit).Offset(offset).Find(&users)
	if result.Error != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		log.WithFields(logrus.Fields{
			"action": "fetchUsers",
			"status": "failed",
			"error":  result.Error.Error(),
		}).Error("Failed to fetch users")
		return
	}

	log.WithFields(logrus.Fields{
		"action": "fetchUsers",
		"status": "success",
		"count":  len(users),
	}).Info("Users fetched successfully")

	// Return users in the response
	json.NewEncoder(w).Encode(Response{
		Status: "success",
		Users:  users,
	})
}

// Main function
func main() {
	// Initialize the database
	initDatabase()

	// Define routes with Rate Limiting Middleware
	http.HandleFunc("/add-user", rateLimitMiddleware(addUserHandler))
	http.HandleFunc("/delete-user", rateLimitMiddleware(deleteUserHandler))
	http.HandleFunc("/update-user", rateLimitMiddleware(updateUserHandler))
	http.HandleFunc("/get-user", rateLimitMiddleware(getUserByIDHandler))
	http.HandleFunc("/fst", rateLimitMiddleware(FST))

	// Enable CORS for all origins
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	// Wrap the default HTTP handler with CORS
	handler := c.Handler(http.DefaultServeMux)

	// Start the server
	fmt.Println("Server is running on http://localhost:8080")
	log.WithField("action", "startServer").Info("Server started on port 8080")
	http.ListenAndServe(":8080", handler)
}
