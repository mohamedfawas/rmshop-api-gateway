package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/client"
	adminv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/admin"
	authv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/auth"
	userv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/user"
)

// to communicate with other services
type Handler struct {
	clients *client.GrpcClients
}

// Instance with provided grpc clients
func NewHandler(clients *client.GrpcClients) *Handler {
	return &Handler{clients: clients}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	// Auth routes
	r.POST("/auth/login", h.Login)
	r.POST("/auth/logout", h.AuthMiddleware(), h.Logout)

	// User routes
	r.POST("/users", h.CreateUser)
	r.GET("/users/me", h.AuthMiddleware(), h.GetUserInfo)

	// Admin routes
	adminGroup := r.Group("/admin")
	adminGroup.Use(h.AdminAuthMiddleware())
	{
		adminGroup.GET("/users/:id", h.GetUserDetails)
	}
}

// Login handles user authentication
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.clients.Auth.Login(c.Request.Context(), &authv1.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":     resp.Token,
		"user_id":   resp.UserId,
		"user_type": resp.UserType,
	})
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	_, err := h.clients.Auth.Logout(c.Request.Context(), &authv1.LogoutRequest{
		Token: token,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// CreateUser handles user registration
func (h *Handler) CreateUser(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.clients.User.CreateUser(c.Request.Context(), &userv1.CreateUserRequest{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user_id": resp.UserId})
}

// GetUserInfo returns the current user's information
func (h *Handler) GetUserInfo(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	resp, err := h.clients.User.GetUserInfo(c.Request.Context(), &userv1.GetUserInfoRequest{
		UserId: userID,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         resp.Id,
		"name":       resp.Name,
		"email":      resp.Email,
		"created_at": resp.CreatedAt,
	})
}

// GetUserDetails returns user details (admin only)
func (h *Handler) GetUserDetails(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	resp, err := h.clients.Admin.GetUserDetails(c.Request.Context(), &adminv1.GetUserDetailsRequest{
		UserId: userID,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user details"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         resp.User.Id,
		"name":       resp.User.Name,
		"email":      resp.User.Email,
		"created_at": resp.User.CreatedAt,
	})
}

// AuthMiddleware validates the JWT token
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		token = strings.TrimPrefix(token, "Bearer ")
		resp, err := h.clients.Auth.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{
			Token: token,
		})

		if err != nil || !resp.IsValid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", resp.UserId)
		c.Set("user_type", resp.UserType)
		c.Next()
	}
}

// AdminAuthMiddleware ensures the user is an admin
func (h *Handler) AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.AuthMiddleware()(c)
		if c.IsAborted() {
			return
		}

		userType := c.GetString("user_type")
		if userType != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}
