package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"speech/config"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	"speech/infrastructure/pq4"
)

// User represents the user model
type User struct {
	ID           string         `json:"id"`
	Username     string         `json:"username"`
	Email        string         `json:"email"`
	PasswordHash string         `json:"-"`
	Bio          sql.NullString `json:"bio"`
	IsVerified   bool           `json:"is_verified"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// AnonymousProfile represents the anonymous profile model
type AnonymousProfile struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Nickname  string    `json:"nickname"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var db *sql.DB
var jwtSecret = []byte("your-secret-key") // In production, use a secure method to store this

func mainJson() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err = sql.Open("postgres", "user=postgres password=12345 dbname=speech_temp sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal("Error closing database connection")
		}
	}(db)

	_ = InitializeAppWire(db, cfg)

	// Initialize router
	r := mux.NewRouter()

	// Routes
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/profile", createAnonymousProfileHandler).Methods("POST")
	r.HandleFunc("/profile", getAnonymousProfileHandler).Methods("GET")
	r.HandleFunc("/exchange", e521KeyExchangeHandler).Methods("GET")

	// Load TLS certificates
	cert, err := tls.LoadX509KeyPair("/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.crt", "/Users/usmanakhmedov/FleetProjects/speech/speech_wtf.key")
	if err != nil {
		log.Fatalf("Failed to load server certificates: %v", err)
	}

	// Create a certificate pool and add the client's certificate
	clientCAs := x509.NewCertPool()
	clientCert, err := os.ReadFile("/Users/usmanakhmedov/FleetProjects/speech/client.crt")
	if err != nil {
		log.Fatalf("Failed to read client certificate: %v", err)
	}
	clientCAs.AppendCertsFromPEM(clientCert)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			log.Println("Verifying peer certificate")
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					log.Printf("Failed to parse certificate: %v", err)
					continue
				}
				log.Printf("Client certificate %d: Subject: %s, Issuer: %s", i+1, cert.Subject, cert.Issuer)
			}
			return nil
		},
	}

	// Enable TLS debugging
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		log.Printf("TLS Handshake: Version: %d, CipherSuite: %d", cs.Version, cs.CipherSuite)
		log.Printf("Client certificates provided: %d", len(cs.PeerCertificates))
		log.Printf("Negotiated protocol: %s", cs.NegotiatedProtocol)
		log.Printf("Server name: %s", cs.ServerName)
		return nil
	}

	// Add a simple handler for testing
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on /")
		w.Write([]byte("Hello, TLS!"))
	})

	// Create HTTPS server
	server := &http.Server{
		Addr:      ":8443",
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	// Start server
	log.Println("Starting server on :8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func e521KeyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	// Generate server's E521 key pair
	privateKey, publicKey, err := pq4.GenerateE521KeyPair()
	if err != nil {
		http.Error(w, "Failed to generate key pair", http.StatusInternalServerError)
		return
	}

	// Serialize the public key
	serializedPublicKey := pq4.SerializePoint(publicKey)

	// Send the public key to the client
	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(serializedPublicKey)
	if err != nil {
		return
	}

	// In a real-world scenario, you'd store the private key securely for later use
	// For this example, we'll just log it (DO NOT do this in production!)
	log.Printf("Server private key: %v", privateKey)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user User
	err = db.QueryRow("SELECT id, password_hash FROM users WHERE username = $1", loginData.Username).Scan(&user.ID, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error querying database", http.StatusInternalServerError)
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginData.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func createAnonymousProfileHandler(w http.ResponseWriter, r *http.Request) {
	var profile AnonymousProfile
	err := json.NewDecoder(r.Body).Decode(&profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user ID from JWT
	userID, err := getUserIDFromToken(r)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Save profile to database
	err = db.QueryRow("INSERT INTO anonymous_profiles (user_id, nickname) VALUES ($1, $2) RETURNING id",
		userID, profile.Nickname).Scan(&profile.ID)
	if err != nil {
		http.Error(w, "Error creating profile", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(profile)
}

func getAnonymousProfileHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromToken(r)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var profile AnonymousProfile
	err = db.QueryRow("SELECT id, nickname FROM anonymous_profiles WHERE user_id = $1", userID).Scan(&profile.ID, &profile.Nickname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Profile not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error querying database", http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(profile)
}

func getUserIDFromToken(r *http.Request) (string, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return "", jwt.ErrSignatureInvalid
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["user_id"].(string), nil
	}

	return "", jwt.ErrSignatureInvalid
}
