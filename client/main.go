package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"speech_client/pq4"
	"time"

	"google.golang.org/grpc"
	pb "speech_client/proto"
)

var (
	serverAddr = flag.String("server_addr", "0.0.0.0:8080", "The server address in the format of host:port")
	certFile   = flag.String("/Users/usmanakhmedov/FleetProjects/speech/client.crt", "/Users/usmanakhmedov/FleetProjects/speech/client.crt", "The server TLS certificate file")
)

func main() {
	flag.Parse()

	// Load the server's certificate
	cert, err := ioutil.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(cert) {
		log.Fatalf("Failed to add server certificate to pool")
	}

	// Create TLS credentials
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	})

	// Establish a connection to the server
	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create clients for each service
	userClient := pb.NewUserAccountServiceClient(conn)
	authClient := pb.NewAuthenticationServiceClient(conn)

	// Demonstrate user registration
	user, err := registerUser(userClient)
	if err != nil {
		log.Fatalf("Failed to register user: %v", err)
	}
	log.Printf("Registered user: %v", user.Username)

	// Demonstrate user login
	tokens, err := loginUser(authClient, user.Email, "password123")
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}
	log.Printf("Logged in successfully. Access token: %v", tokens.AccessToken)

	// Demonstrate user logout
	err = logoutUser(authClient, tokens.AccessToken)
	if err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}
	log.Println("Logged out successfully")
}

func registerUser(client pb.UserAccountServiceClient) (*pb.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// User input (in a real application, these would come from user interface)
	username := "alice"
	email := "alice@example.com"
	bio := "Crypto enthusiast"
	password := "super-secret-password"

	// Generate salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// Generate encryption key
	encryptionKey := pq4.ArgonPassword([]byte(password), salt)

	// Generate cryptographic keys
	identityPrivKey, identityPubKey, err := pq4.GenerateE521KeyPair()
	if err != nil {
		log.Fatalf("Failed to generate identity key pair: %v", err)
	}

	signedPreKeyPriv, signedPreKeyPub, err := pq4.GenerateE521KeyPair()
	if err != nil {
		log.Fatalf("Failed to generate signed pre-key pair: %v", err)
	}

	// Generate one-time pre-keys (let's generate 3 for this example)
	var oneTimePreKeys [][]byte
	for i := 0; i < 3; i++ {
		_, pubKey, err := pq4.GenerateE521KeyPair()
		if err != nil {
			log.Fatalf("Failed to generate one-time pre-key pair: %v", err)
		}
		oneTimePreKeys = append(oneTimePreKeys, pq4.SerializePoint(pubKey))
	}

	// Generate Kyber key pair
	kyberPub, kyberPriv, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	kyberPubBytes := make([]byte, kyber1024.PublicKeySize)
	kyberPub.Pack(kyberPubBytes)

	// Sign the signed pre-key
	signedPreKeySig, err := pq4.SignMessage(identityPrivKey, pq4.SerializePoint(signedPreKeyPub))
	if err != nil {
		log.Fatalf("Failed to sign pre-key: %v", err)
	}

	// Encrypt private keys
	privateKeys := map[string]interface{}{
		"identity_key":      identityPrivKey,
		"signed_pre_key":    signedPreKeyPriv,
		"kyber_private_key": kyberPriv,
	}
	privateKeysJSON, err := json.Marshal(privateKeys)
	if err != nil {
		log.Fatalf("Failed to marshal private keys: %v", err)
	}
	encryptedPrivateKeys, err := pq4.Encrypt(encryptionKey, privateKeysJSON, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt private keys: %v", err)
	}

	// Compute password HMAC
	passwordHMAC, err := pq4.HmacPassword([]byte(password), salt)
	if err != nil {
		log.Fatalf("Failed to compute password HMAC: %v", err)
	}

	// Build the CreateUserRequest
	request := &pb.CreateUserRequest{
		Username:              username,
		Email:                 email,
		Bio:                   &bio, // Using a pointer for optional field
		PasswordHmac:          passwordHMAC,
		Salt:                  salt,
		PublicIdentityKey:     pq4.SerializePoint(identityPubKey),
		PublicSignedPreKey:    pq4.SerializePoint(signedPreKeyPub),
		SignedPreKeySignature: signedPreKeySig,
		PublicOneTimePreKeys:  oneTimePreKeys,
		PublicKyberKey:        kyberPubBytes,
		EncryptedPrivateKeys:  encryptedPrivateKeys,
	}

	resp, err := client.CreateUser(ctx, request)
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

func loginUser(client pb.AuthenticationServiceClient, email, password string) (*pb.LoginResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	return client.Login(ctx, &pb.LoginRequest{
		Email:    email,
		Password: password,
	})
}

func logoutUser(client pb.AuthenticationServiceClient, accessToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.Logout(ctx, &pb.LogoutRequest{
		AccessToken: accessToken,
	})
	return err
}
