package controllers

import (
	"database/sql"
	"net/http"
	"os"
	"time"

	"gin-auth/config"
	"gin-auth/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Generate Access Token & Refresh Token
// func generateToken(userID int, role string) (string, string, error) {
// 	// Access Token (15 menit)
// 	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"user_id": userID,
// 		"role":    role,
// 		"exp":     time.Now().Add(15 * time.Minute).Unix(),
// 	})

// 	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
// 	if err != nil {
// 		return "", "", err
// 	}

// 	// Refresh Token (7 hari)
// 	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"user_id": userID,
// 		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
// 	})

// 	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
// 	if err != nil {
// 		return "", "", err
// 	}

// 	return accessTokenString, refreshTokenString, nil
// }

func generateToken(userID int, role string) (string, string, error) {
	// Access Token (15 menit)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", "", err
	}

	// Refresh Token (7 hari)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// Register User
func Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	_, err = config.DB.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", user.Username, string(hashedPassword), "user")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// Login User
// func Login(c *gin.Context) {
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
// 		return
// 	}

// 	var storedUser models.User
// 	err := config.DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = $1", user.Username).Scan(
// 		&storedUser.ID, &storedUser.Username, &storedUser.Password, &storedUser.Role,
// 	)
// 	if err == sql.ErrNoRows {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
// 		return
// 	} else if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
// 		return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
// 		return
// 	}

// 	// Generate tokens
// 	accessToken, refreshToken, err := generateToken(storedUser.ID, storedUser.Role)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
// 		return
// 	}

// 	// Simpan refresh token ke database
// 	_, err = config.DB.Exec("UPDATE users SET refresh_token = $1 WHERE id = $2", refreshToken, storedUser.ID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	})
// }

func Login(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedUser models.User
	err := config.DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = $1", user.Username).
		Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password, &storedUser.Role)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
		return
	}

	// Cek password
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate access token & refresh token
	accessToken, refreshToken, err := generateToken(storedUser.ID, storedUser.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	// Simpan refresh token ke database
	_, err = config.DB.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		storedUser.ID, refreshToken, time.Now().Add(7*24*time.Hour))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Refresh Token
// func RefreshToken(c *gin.Context) {
// 	var requestBody struct {
// 		RefreshToken string `json:"refresh_token"`
// 	}
// 	if err := c.ShouldBindJSON(&requestBody); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
// 		return
// 	}

// 	// Validasi refresh token
// 	token, err := jwt.Parse(requestBody.RefreshToken, func(token *jwt.Token) (interface{}, error) {
// 		return []byte(os.Getenv("JWT_SECRET")), nil
// 	})
// 	if err != nil || !token.Valid {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
// 		return
// 	}

// 	claims, _ := token.Claims.(jwt.MapClaims)
// 	userID := int(claims["user_id"].(float64))

// 	// Cek refresh token di database
// 	var storedRefreshToken string
// 	var role string
// 	err = config.DB.QueryRow("SELECT refresh_token, role FROM users WHERE id = $1", userID).Scan(&storedRefreshToken, &role)
// 	if err != nil || storedRefreshToken != requestBody.RefreshToken {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token mismatch"})
// 		return
// 	}

// 	// Generate tokens baru
// 	accessToken, newRefreshToken, err := generateToken(userID, role)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new tokens"})
// 		return
// 	}

// 	// Simpan refresh token baru ke database
// 	_, err = config.DB.Exec("UPDATE users SET refresh_token = $1 WHERE id = $2", newRefreshToken, userID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"access_token":  accessToken,
// 		"refresh_token": newRefreshToken,
// 	})
// }

func RefreshToken(c *gin.Context) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Parse refresh token
	token, err := jwt.Parse(requestBody.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	// Cek refresh token di database
	var dbRefreshToken string
	var role string
	err = config.DB.QueryRow("SELECT token FROM refresh_tokens WHERE user_id = $1 AND token = $2", userID, requestBody.RefreshToken).
		Scan(&dbRefreshToken)

	if err != nil || dbRefreshToken != requestBody.RefreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token mismatch"})
		return
	}

	// Generate token baru
	accessToken, newRefreshToken, err := generateToken(userID, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new tokens"})
		return
	}

	// Update refresh token di database
	_, err = config.DB.Exec("UPDATE refresh_tokens SET token = $1, expires_at = $2 WHERE user_id = $3 AND token = $4",
		newRefreshToken, time.Now().Add(7*24*time.Hour), userID, requestBody.RefreshToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

func Logout(c *gin.Context) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Hapus refresh token dari database
	_, err := config.DB.Exec("DELETE FROM refresh_tokens WHERE token = $1", requestBody.RefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
