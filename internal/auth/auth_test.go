package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	secret := "mysecretkey"
	userID := uuid.New()
	expiresIn := time.Hour

	// Create a JWT.
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Validate the JWT.
	returnedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if returnedID != userID {
		t.Errorf("Expected userID %v, got %v", userID, returnedID)
	}
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	secret := "mysecretkey"
	wrongSecret := "incorrectkey"
	userID := uuid.New()
	expiresIn := time.Hour

	// Create a valid token with the correct secret.
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Validate the token with the wrong secret; expecting an error.
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("Expected an error when validating with wrong secret, got nil")
	}
}

func TestValidateExpiredJWT(t *testing.T) {
	secret := "mysecretkey"
	userID := uuid.New()
	// Create a token that expires in the past.
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Validate the expired token; expecting an error.
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("Expected an error when validating an expired token, got nil")
	}
}

func TestGetBearerToken_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer mytoken123")
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token != "mytoken123" {
		t.Errorf("expected token 'mytoken123', got %q", token)
	}
}

func TestGetBearerToken_InsufficientParts(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer")
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestGetBearerToken_MissingHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestGetBearerToken_NonBearer(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Basic sometoken")
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
