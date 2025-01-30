package main

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestGetUserHandler(t *testing.T) {
    req, err := http.NewRequest("GET", "/user/1", nil)
    if err != nil {
        t.Fatalf("Could not create request: %v", err)
    }

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(GetUserHandler)
    handler.ServeHTTP(rr, req)

    expected := `{"user":{"id":1,"name":"John Doe","email":"john@example.com"}}`
    if rr.Body.String() != expected {
        t.Errorf("Incorrect response body. Expected: %s, Got: %s", expected, rr.Body.String())
    }
}


    req, _ := http.NewRequest("GET", "/user/1", nil)
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(GetUserHandler)
    handler.ServeHTTP(rr, req)

    expected := `{"user":{"id":1,"name":"John Doe","email":"john@example.com"}}`
    if rr.Body.String() != expected {
    t.Errorf("Incorrect response body. Expected: %s, Got: %s", expected, rr.Body.String())
    }

