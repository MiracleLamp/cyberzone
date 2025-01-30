package main

import "testing"



func TestCalculateRentalCost(t *testing.T) {
    cost := CalculateRentalCost(5, 100.0)
    if cost != 500.0 {
        t.Errorf("Expected 500.0, got %f", cost)
    }
}

func CalculateRentalCost(days int, rate float64) float64 {
    return float64(days) * rate
}

