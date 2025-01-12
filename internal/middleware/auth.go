package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mohamedfawas/rmshop-api-gateway/internal/client"
	authv1 "github.com/mohamedfawas/rmshop-proto/gen/auth/v1"
)

type AuthMiddleware struct {
	authClient authv1.AuthServiceClient
}

func NewAuthMiddleware(clients *client.GRPCClients) *AuthMiddleware {
	return &AuthMiddleware{
		authClient: clients.AuthClient,
	}
}

func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractToken(c)
		if token == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized - No token provided"})
			return
		}

		// Validate token with auth service
		resp, err := m.authClient.ValidateToken(c.Request.Context(), &authv1.ValidateTokenRequest{
			Token: token,
		})

		if err != nil || !resp.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized - Invalid token"})
			return
		}

		// Store user information in context
		c.Set("user_id", resp.UserId)
		if len(resp.Permissions) > 0 {
			c.Set("permissions", resp.Permissions)
		}

		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if bearerToken == "" {
		return ""
	}

	parts := strings.Split(bearerToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

// Optional: Add role-based middleware
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - No permissions found"})
			return
		}

		userRoles, ok := permissions.([]string)
		if !ok {
			c.AbortWithStatusJSON(500, gin.H{"error": "Internal server error - Invalid permissions format"})
			return
		}

		for _, role := range roles {
			for _, userRole := range userRoles {
				if userRole == role {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - Insufficient permissions"})
	}
}
