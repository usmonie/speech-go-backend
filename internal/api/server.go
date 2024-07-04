package api

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"os"
	"speech/internal/auth"
	"speech/internal/cache"
	"speech/internal/database"
	"speech/internal/user"
)

type Server struct {
	router *gin.Engine
	db     *database.Database
	cache  *cache.RedisCache
}

func NewServer(db *database.Database, cache *cache.RedisCache) *Server {
	router := gin.New()
	router.Use(Logger())
	router.Use(RateLimitMiddleware(10)) // Limit to 10 requests per second

	server := &Server{
		router: router,
		db:     db,
		cache:  cache,
	}
	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	s.router.GET("/health", s.healthCheck)

	// Group for authenticated routes
	authRoute := s.router.Group("/")
	authRoute.Use(AuthMiddleware())
	{
		authRoute.GET("/protected", s.protectedEndpoint)
		authRoute.POST("/users", s.createUser)
		s.router.POST("/register", s.registerUser)
		s.router.POST("/login", s.login)
		s.router.POST("/refresh", s.refreshToken)
		s.router.POST("/logout", s.logout)
	}
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

func (s *Server) protectedEndpoint(c *gin.Context) {
	userID, _ := c.Get("userID")
	c.JSON(200, gin.H{
		"message": "This is a protected endpoint",
		"userID":  userID,
	})
}

func (s *Server) registerUser(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create user
	userService := user.NewService(s.db)
	newUser, err := userService.CreateUser(user.CreateUserInput{
		Username: input.Username,
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user_id": newUser.ID})
}

func (s *Server) login(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authService := auth.NewService(s.db)
	tokens, err := authService.Login(input.Email, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *Server) refreshToken(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authService := auth.NewService(s.db)
	tokens, err := authService.RefreshToken(input.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (s *Server) logout(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authService := auth.NewService(s.db)
	if err := authService.Logout(input.RefreshToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
