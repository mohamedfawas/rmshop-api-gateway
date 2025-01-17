package config

import (
	"os"
)

type Config struct {

	// api gateway's server settings
	// combination of Host and Port determines the API Gateway's endpoint , http://localhost:8080
	Server struct {
		Port string // api gateway's server will run on this port
		Host string // host address of the API Gateway server
	}
	Services struct {
		Auth  string // Auth service address
		Admin string // Admin service address
		User  string // User service address
	}
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Server config
	cfg.Server.Host = getEnvOrDefault("SERVER_HOST", "0.0.0.0")
	cfg.Server.Port = getEnvOrDefault("SERVER_PORT", "8080")

	// Services config
	cfg.Services.Auth = getEnvOrDefault("AUTH_SERVICE_ADDR", "auth-service:50051")
	cfg.Services.Admin = getEnvOrDefault("ADMIN_SERVICE_ADDR", "admin-service:50052")
	cfg.Services.User = getEnvOrDefault("USER_SERVICE_ADDR", "user-service:50053")

	return cfg, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
