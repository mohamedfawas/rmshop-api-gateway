package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/client"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/config"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/handler"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize gRPC clients
	clients, err := client.NewGrpcClients(
		cfg.Services.Auth,
		cfg.Services.Admin,
		cfg.Services.User,
	)
	if err != nil {
		log.Fatalf("Failed to create gRPC clients: %v", err)
	}

	// Initialize Gin router
	r := gin.Default()

	// Initialize and register handlers
	h := handler.NewHandler(clients)
	h.RegisterRoutes(r)

	// Start server
	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("Starting API Gateway on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start API Gateway server: %v", err)
	}
}
