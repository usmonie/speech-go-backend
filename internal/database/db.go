package database

import (
	"fmt"
	"log"
//	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Database struct {
	*gorm.DB
}

func NewDatabase() (*Database, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=5432 sslmode=disable TimeZone=UTC",
		"localhost",
		"postgres",
		"12345",
		"users",
		//		os.Getenv("DB_HOST"),
		//		os.Getenv("DB_USER"),
		//		os.Getenv("DB_PASSWORD"),
		//		os.Getenv("DB_NAME"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxIdleConns(10)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(100)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Hour)

	log.Println("Connected to database successfully")

	return &Database{db}, nil
}

func (db *Database) Migrate() error {
	err := db.AutoMigrate(&User{}, &Message{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	log.Println("Database migration completed")
	return nil
}

// User is an example model
type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex;not null"`
	Email    string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
}

type Message struct {
	gorm.Model
	SenderID    uint   `gorm:"not null"`
	RecipientID uint   `gorm:"not null"`
	Content     string `gorm:"not null"`
}
