package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)


func signUpHandler(w http.ResponseWriter, r *http.Request) {
	writeLog("info", "Received Sign Up request")
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeLog("error", "Invalid input for Sign Up")
		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
		return
	}

	// Validate input fields
	if user.Name == "" || user.Email == "" || user.Password == "" || user.Role == "" {
		writeLog("error", "Missing required fields in Sign Up")
		http.Error(w, `{"error":"Missing required fields"}`, http.StatusBadRequest)
		return
	}

	if user.Role != "User" && user.Role != "Admin" {
		writeLog("error", "Invalid role in Sign Up")
		http.Error(w, `{"error":"Invalid role"}`, http.StatusBadRequest)
		return
	}

	// Check if email already exists
	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		writeLog("error", "Email already exists during Sign Up")
		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
		return
	}

	if err := db.Create(&user).Error; err != nil {
		writeLog("error", "Failed to create user during Sign Up")
		http.Error(w, `{"error":"Failed to create user"}`, http.StatusInternalServerError)
		return
	}

	writeLog("info", fmt.Sprintf("User signed up successfully: %v", user))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	writeLog("info", "Received Login request")
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		writeLog("error", "Invalid input for Login")
		http.Error(w, `{"error":"Invalid input format"}`, http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		writeLog("error", "Email not found during Login")
		http.Error(w, `{"error":"You are not registered. Please sign up first."}`, http.StatusUnauthorized)
		return
	}

	if user.Password != credentials.Password {
		writeLog("error", "Invalid password during Login")
		http.Error(w, `{"error":"Incorrect password"}`, http.StatusUnauthorized)
		return
	}

	writeLog("info", fmt.Sprintf("User logged in successfully: %v", user))
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"role":    user.Role, 
	})
}
