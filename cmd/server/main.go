package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/client"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/config"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/handler"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set Gin mode
	gin.SetMode(cfg.Mode)

	// Initialize gRPC clients
	clients, err := client.NewGRPCClients(
		cfg.AuthServiceURL,
		cfg.UserServiceURL,
		cfg.AdminServiceURL,
	)
	if err != nil {
		log.Fatalf("Failed to initialize gRPC clients: %v", err)
	}
	defer clients.Close()

	// Initialize handlers and middleware
	h := handler.NewHandler(clients)
	auth := middleware.NewAuthMiddleware(clients)

	// Initialize Gin router
	r := gin.Default()

	// Add global middleware
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// API routes
	api := r.Group("/api/v1")
	{
		// Public routes
		api.POST("/auth/login", h.Login)
		api.POST("/users", h.CreateUser)

		// Protected routes
		authenticated := api.Group("")
		authenticated.Use(auth.Authenticate())
		{
			// User routes
			authenticated.GET("/users/:id", h.GetUser)

			// Admin routes
			adminRoutes := authenticated.Group("/admins")
			adminRoutes.Use(middleware.RequireRole("admin"))
			{
				adminRoutes.POST("/", h.CreateAdmin)
				adminRoutes.GET("/:id", h.GetAdmin)
			}
		}
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// Start server
	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	log.Printf("Starting HTTP server on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
