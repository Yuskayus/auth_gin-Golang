package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware memverifikasi JWT dan menyimpan user_id serta role dalam context
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Missing Token"})
			c.Abort()
			return
		}

		// Format token harus "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Invalid Token Format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validasi token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Invalid Token"})
			c.Abort()
			return
		}

		// Ambil claims dari token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Invalid Token Claims"})
			c.Abort()
			return
		}

		// Ambil user_id dan role dari token
		userID, userIDOk := claims["user_id"].(float64)
		role, roleOk := claims["role"].(string)

		if !userIDOk || !roleOk {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Invalid Token Data"})
			c.Abort()
			return
		}

		// Simpan user_id dan role dalam context Gin untuk digunakan di endpoint lain
		c.Set("user_id", int(userID))
		c.Set("role", role)

		c.Next()
	}
}

// RoleMiddleware membatasi akses berdasarkan role tertentu
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ambil role dari context yang sudah diset di AuthMiddleware
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden - Role Not Found"})
			c.Abort()
			return
		}

		// Cek apakah user memiliki role yang diperlukan
		if role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden - Insufficient Permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}
