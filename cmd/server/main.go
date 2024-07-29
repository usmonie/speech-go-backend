package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"speech/internal/auth"
	"speech/internal/email"
	"speech/internal/proto"
	"speech/internal/user"
	"syscall"
	"time"

	"speech/config"
	"speech/infrastructure/connection"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type AppServices struct {
	credentials      credentials.TransportCredentials
	authService      *auth.Handler
	authJsonService  *auth.JSONHandler
	emailService     *email.Handler
	emailJsonService *email.JSONHandler
	userService      *user.Handler
	userJsonService  *user.JSONHandler
}

// TODO: add fully stream messaging service to update information about user's online status and etc
func main() {
	// Load TLS certificates
	cert, err := tls.LoadX509KeyPair(
		"/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.crt",
		"/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.key",
	)
	if err != nil {
		log.Fatalf("Failed to load server certificates: %v", err)
	}

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

	appServices := InitializeAppWire(db, cfg)
	combinedInterceptor := chainUnaryInterceptors(connection.AuthenticationInterceptor, loggingUnaryInterceptor)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		//grpc.Creds(appServices.credentials),
		grpc.UnaryInterceptor(combinedInterceptor),
		grpc.StreamInterceptor(loggingStreamInterceptor),
	)

	// Register auth service
	proto.RegisterAuthenticationServiceServer(grpcServer, appServices.authService)
	proto.RegisterUserAccountServiceServer(grpcServer, appServices.userService)
	proto.RegisterEmailServiceServer(grpcServer, appServices.emailService)

	reflection.Register(grpcServer)

	// Create gRPC-Web wrapper
	wrappedGrpc := grpcweb.WrapServer(grpcServer)

	// Create router for HTTP/JSON API
	router := mux.NewRouter()

	user.SetupJSONRoutes(router, appServices.userJsonService)
	auth.SetupJSONAuthRoutes(router, appServices.authJsonService)
	email.SetupJSONEmailRoutes(router, appServices.emailJsonService)

	// Create a new http.ServeMux
	serveMux := http.NewServeMux()

	// Handle gRPC-Web requests
	serveMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		println("Started request")
		if wrappedGrpc.IsGrpcWebRequest(r) {
			wrappedGrpc.ServeHTTP(w, r)
			return
		}
		// Serve HTTP/JSON API
		router.ServeHTTP(w, r)
	}))

	// Create HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Port),
		Handler: serveMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		},
	}

	// Start server
	go func() {
		log.Printf("Server listening on port %s", cfg.Port)
		if err := srv.ListenAndServeTLS("/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.crt", "/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.key"); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Server is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")

	lis, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting gRPC server on :%s", cfg.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// loggingUnaryInterceptor logs information about unary RPC calls
func loggingUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	duration := time.Since(start)

	statusCode := status.Code(err)
	log.Printf("Unary RPC: %s, Duration: %v, Status: %s", info.FullMethod, duration, statusCode)

	return resp, err
}

// loggingStreamInterceptor logs information about streaming RPC calls
func loggingStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	start := time.Now()
	err := handler(srv, ss)
	duration := time.Since(start)

	statusCode := status.Code(err)
	log.Printf("Streaming RPC: %s, Duration: %v, Status: %s", info.FullMethod, duration, statusCode)

	return err
}

// chainUnaryInterceptors creates a single interceptor from multiple interceptors
func chainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		chain := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			chain = func(currentInter grpc.UnaryServerInterceptor, nextHandler grpc.UnaryHandler) grpc.UnaryHandler {
				return func(currentCtx context.Context, currentReq interface{}) (interface{}, error) {
					return currentInter(currentCtx, currentReq, info, nextHandler)
				}
			}(interceptors[i], chain)
		}
		return chain(ctx, req)
	}
}
