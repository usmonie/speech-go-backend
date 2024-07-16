package main

import (
	"database/sql"
	"log"
	"net"
	"speech/internal/auth/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"speech/config"
	"speech/internal/auth"
	"speech/internal/chat"
)

// TODO: add fully stream messaging service to update information about user's online status and etc

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := sql.Open("postgres", "user=postgres password=12345 dbname=speech_temp sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal("Error closing database connection")
		}
	}(db)
	//
	//	authHandler, err := di.InitializeAuthHandler(cfg, db)
	//	if err != nil {
	//		log.Fatalf("Failed to initialize auth handler: %v", err)
	//	}

	userService := InitializeAppWire(db, cfg)

	// Initialize chat components
	chatRepo := chat.NewPostgresRepository(db)
	chatService := chat.NewChatService(chatRepo)
	chatHandler := chat.NewChatHandler(chatService)

	//	authMiddleware := auth.NewAuthMiddleware(cfg.JWTSecret)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(auth.AuthenticationInterceptor),
	)

	// Register auth service
	proto.RegisterUserServiceServer(grpcServer, userService)
	//	auth.RegisterAuthServiceServer(grpcServer, authHandler)

	// Register chat services
	chat.RegisterChatServiceServer(grpcServer, chatHandler)
	chat.RegisterUserStatusServiceServer(grpcServer, chatHandler)

	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting gRPC server on :%s", cfg.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
