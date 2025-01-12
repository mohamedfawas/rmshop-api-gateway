package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	// Server configurations
	HTTPPort int
	Mode     string // gin mode (debug/release)

	// Service URLs
	AuthServiceURL  string
	UserServiceURL  string
	AdminServiceURL string

	// JWT configurations
	JWTSecret string
}

func LoadConfig() (*Config, error) {
	config := &Config{}

	// Server configurations
	port, err := strconv.Atoi(getEnvOrDefault("HTTP_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP_PORT: %v", err)
	}
	config.HTTPPort = port
	config.Mode = getEnvOrDefault("GIN_MODE", "debug")

	// Service URLs
	config.AuthServiceURL = getEnvOrDefault("AUTH_SERVICE_URL", "localhost:50051")
	config.UserServiceURL = getEnvOrDefault("USER_SERVICE_URL", "localhost:50052")
	config.AdminServiceURL = getEnvOrDefault("ADMIN_SERVICE_URL", "localhost:50053")

	// JWT configurations
	config.JWTSecret = os.Getenv("JWT_SECRET")
	if config.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}

	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
