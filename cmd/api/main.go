package main

import (
	"log"

	"speech/internal/api"
	"speech/internal/cache"
	"speech/internal/database"
)

func main() {
	// Initialize database
	db, err := database.NewDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	// Initialize Redis cache
	redisCache, err := cache.NewRedisCache()
	if err != nil {
		log.Fatalf("Failed to initialize Redis cache: %v", err)
	}

	// Initialize server
	server := api.NewServer(db, redisCache)

	log.Println("Starting server on :8080")
	if err := server.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
