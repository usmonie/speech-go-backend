package pq4

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"strconv"
)

var (
	e521P, _     = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10)
	e521D        = big.NewInt(-376014)
	e521Order, _ = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10)
)

type E521Point struct {
	X, Y *big.Int
}

func GenerateE521KeyPair() (*big.Int, *E521Point, error) {
	privateKey, err := rand.Int(rand.Reader, e521Order)
	if err != nil {
		return nil, nil, err
	}

	publicKey := ScalarMult(privateKey, &E521Point{big.NewInt(4), big.NewInt(0)})
	return privateKey, publicKey, nil
}

func ScalarMult(k *big.Int, p *E521Point) *E521Point {
	result := &E521Point{X: big.NewInt(0), Y: big.NewInt(1)}
	temp := &E521Point{X: p.X, Y: p.Y}

	for i := k.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 1 {
			result = AddPoints(result, temp)
		}
		temp = AddPoints(temp, temp)
	}

	return result
}

func AddPoints(p1, p2 *E521Point) *E521Point {
	x1, y1, x2, y2 := p1.X, p1.Y, p2.X, p2.Y

	x3 := new(big.Int).Sub(
		new(big.Int).Mul(x1, y2),
		new(big.Int).Mul(y1, x2),
	)
	y3 := new(big.Int).Add(
		new(big.Int).Mul(x1, x2),
		new(big.Int).Mul(y1, y2),
	)

	z := new(big.Int).Add(
		big.NewInt(1),
		new(big.Int).Mul(
			e521D,
			new(big.Int).Mul(
				new(big.Int).Mul(x1, x2),
				new(big.Int).Mul(y1, y2),
			),
		),
	)

	x3.Mod(x3, e521P)
	y3.Mod(y3, e521P)
	z.ModInverse(z, e521P)

	x3.Mul(x3, z).Mod(x3, e521P)
	y3.Mul(y3, z).Mod(y3, e521P)

	return &E521Point{x3, y3}
}

func (p *E521Point) Equals(other *E521Point) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// SerializePoint converts an E521Point to a byte slice
func SerializePoint(p *E521Point) []byte {
	bytes := make([]byte, 132)
	p.X.FillBytes(bytes[:66])
	p.Y.FillBytes(bytes[66:])
	return bytes
}

// DeserializePoint converts a byte slice to an E521Point
func DeserializePoint(data []byte) (*E521Point, error) {
	if len(data) != 132 {
		return nil, errors.New("invalid point data length")
	}
	x := new(big.Int).SetBytes(data[:66])
	y := new(big.Int).SetBytes(data[66:])
	return &E521Point{X: x, Y: y}, nil
}

// GenerateSharedSecret computes the shared secret given a private key and a public key
func GenerateSharedSecret(privateKey *big.Int, publicKey *E521Point) []byte {
	sharedPoint := ScalarMult(privateKey, publicKey)
	return SerializePoint(sharedPoint)
}

// SignMessage signs a message using the private key
func SignMessage(privateKey *big.Int, message []byte) ([]byte, error) {
	// This is a simplified ECDSA-like signing process
	r, s := new(big.Int), new(big.Int)

	// Generate a random k
	k, err := rand.Int(rand.Reader, e521Order)
	if err != nil {
		return nil, err
	}

	// Calculate r = (k * G).x mod n
	kG := ScalarMult(k, &E521Point{big.NewInt(4), big.NewInt(0)})
	r.Set(kG.X).Mod(r, e521Order)

	// Calculate s = k^-1 * (hash(m) + r * privateKey) mod n
	h := new(big.Int).SetBytes(message)
	s.Mul(r, privateKey)
	s.Add(s, h)
	kInv := new(big.Int).ModInverse(k, e521Order)
	s.Mul(s, kInv).Mod(s, e521Order)

	// Serialize r and s
	signature := make([]byte, 132)
	r.FillBytes(signature[:66])
	s.FillBytes(signature[66:])

	return signature, nil
}

// VerifySignature verifies a signature against a message and public key
func VerifySignature(publicKey *E521Point, message, signature []byte) bool {
	if len(signature) != 132 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:66])
	s := new(big.Int).SetBytes(signature[66:])

	// Check if r and s are in the correct range
	if r.Cmp(e521Order) >= 0 || s.Cmp(e521Order) >= 0 {
		return false
	}

	// Calculate w = s^-1 mod n
	w := new(big.Int).ModInverse(s, e521Order)

	// Calculate u1 = hash(m) * w mod n
	h := new(big.Int).SetBytes(message)
	u1 := new(big.Int).Mul(h, w)
	u1.Mod(u1, e521Order)

	// Calculate u2 = r * w mod n
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, e521Order)

	// Calculate (u1 * G + u2 * publicKey)
	u1G := ScalarMult(u1, &E521Point{big.NewInt(4), big.NewInt(0)})
	u2PK := ScalarMult(u2, publicKey)
	point := AddPoints(u1G, u2PK)

	// The signature is valid if the x coordinate of the resulting point is equal to r
	return point.X.Cmp(r) == 0
}

// DeriveAESKeyFromPoint derives an AES key from an E521Point, email code, and TOTP code
func DeriveAESKeyFromPoint(point *E521Point, emailCode string, totpCode int) ([]byte, error) {
	// Serialize the X coordinate of the point
	pointBytes := point.X.Bytes()

	// Combine email code, TOTP code, and point
	ikm := append([]byte(emailCode), []byte(strconv.Itoa(totpCode))...)
	ikm = append(ikm, pointBytes...)

	// Use HKDF to derive the key
	hkdf := hkdf.New(sha512.New, ikm, nil, []byte("AES-GCM-KEY"))

	aesKey := make([]byte, 32) // 256-bit key for AES-GCM
	_, err := io.ReadFull(hkdf, aesKey)
	if err != nil {
		return nil, err
	}

	return aesKey, nil
}
