package routes

import (
	"gin-auth/controllers"
	"gin-auth/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// Endpoint tanpa autentikasi
	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)
	r.POST("/refresh", controllers.RefreshToken)

	// Endpoint yang membutuhkan autentikasi
	auth := r.Group("/")
	auth.Use(middleware.AuthMiddleware())
	auth.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")
		c.JSON(200, gin.H{
			"message": "You are authenticated",
			"user_id": userID,
			"role":    role,
		})
	})

	// Endpoint yang hanya bisa diakses oleh admin
	auth.GET("/admin", middleware.RoleMiddleware("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Welcome Admin"})
	})

	return r
}
