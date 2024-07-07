package main

import (
	"database/sql"
	"log"
	"net"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"speech/config"
	"speech/internal/auth"
	"speech/internal/di"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := sql.Open("postgres", "user=postgres password=12345 dbname=speech sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal("Error closing database connection")
		}
	}(db)

	authHandler, err := di.InitializeAuthHandler(cfg, db)
	if err != nil {
		log.Fatalf("Failed to initialize auth handler: %v", err)
	}

	authMiddleware := auth.NewAuthMiddleware(cfg.JWTSecret)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authMiddleware.UnaryInterceptor),
	)
	auth.RegisterAuthServiceServer(grpcServer, authHandler)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", ":" + cfg.Port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting gRPC server on :%s", cfg.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
