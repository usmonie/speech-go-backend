package connection

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"speech/internal/sessions"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
)

// DynamicCreds реализует credentials.TransportCredentials
type DynamicCreds struct {
	getSession sessions.GetSession
	tlsConfig  *tls.Config
}

// NewDynamicCreds создает новый экземпляр DynamicCreds
func NewDynamicCreds(getSession sessions.GetSession, tlsConfig *tls.Config) credentials.TransportCredentials {
	return &DynamicCreds{getSession: getSession, tlsConfig: tlsConfig}
}

// ServerHandshake выполняет рукопожатие на стороне сервера
func (c *DynamicCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// Настраиваем QUIC транспорт
	//quicTransport := &quic.Transport{
	//	TLSServerConfig: c.tlsConfig,
	//}
	//
	//// Принимаем входящее соединение
	//session, err := quicTransport.Accept(context.Background(), rawConn)
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//// Ожидаем открытия потока клиентом
	//stream, err := session.AcceptStream(context.Background())
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//// Читаем идентификатор сессии из первого запроса
	//sessionID, err := readSessionID(stream)
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//// Получаем ключ сессии (это теперь может быть использовано на уровне приложения)
	//_, err = c.getSession.Get(sessionID)
	//if err != nil {
	//	return nil, nil, err
	//}
	//// Возвращаем QUIC stream как net.Conn
	//return &quicConn{stream: stream, session: session}, &authInfo{sessionID: sessionID}, nil

	return nil, nil, nil
}

// ClientHandshake выполняет рукопожатие на стороне клиента
func (c *DynamicCreds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// В этой реализации клиентское рукопожатие не требуется
	return conn, nil, nil
}

// Info возвращает информацию о протоколе безопасности
func (c *DynamicCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "pq4",
		SecurityVersion:  "1.0",
		ServerName:       "speech-wtf-backend",
	}
}

// Clone создает копию DynamicCreds
func (c *DynamicCreds) Clone() credentials.TransportCredentials {
	return &DynamicCreds{getSession: c.getSession}
}

// OverrideServerName переопределяет имя сервера (не используется в этой реализации)
func (c *DynamicCreds) OverrideServerName(serverName string) error {
	return nil
}

// encryptedConn реализует net.Conn с шифрованием
type encryptedConn struct {
	net.Conn
	key   []byte
	gcm   cipher.AEAD
	nonce []byte
	mu    sync.Mutex
}

// newEncryptedConn создает новое зашифрованное соединение
func newEncryptedConn(conn net.Conn, key []byte) (*encryptedConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &encryptedConn{
		Conn:  conn,
		key:   key,
		gcm:   gcm,
		nonce: make([]byte, gcm.NonceSize()),
	}, nil
}

// Read читает и расшифровывает данные
func (c *encryptedConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Читаем размер зашифрованных данных
	sizeBuf := make([]byte, 4)
	_, err = io.ReadFull(c.Conn, sizeBuf)
	if err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(sizeBuf)

	// Читаем nonce
	_, err = io.ReadFull(c.Conn, c.nonce)
	if err != nil {
		return 0, err
	}

	// Читаем зашифрованные данные
	encryptedData := make([]byte, size)
	_, err = io.ReadFull(c.Conn, encryptedData)
	if err != nil {
		return 0, err
	}

	// Расшифровываем данные
	decryptedData, err := c.gcm.Open(nil, c.nonce, encryptedData, nil)
	if err != nil {
		return 0, err
	}

	return copy(b, decryptedData), nil
}

// Write шифрует и записывает данные
func (c *encryptedConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Генерируем новый nonce для каждой записи
	if _, err := io.ReadFull(rand.Reader, c.nonce); err != nil {
		return 0, err
	}

	// Шифруем данные
	encryptedData := c.gcm.Seal(nil, c.nonce, b, nil)

	// Записываем размер зашифрованных данных
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(encryptedData)))
	_, err = c.Conn.Write(sizeBuf)
	if err != nil {
		return 0, err
	}

	// Записываем nonce
	_, err = c.Conn.Write(c.nonce)
	if err != nil {
		return 0, err
	}

	// Записываем зашифрованные данные
	_, err = c.Conn.Write(encryptedData)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// readSessionID читает идентификатор сессии из соединения
func readSessionID(conn net.Conn) (*uuid.UUID, error) {
	// Читаем длину идентификатора сессии
	lenBuf := make([]byte, 4)
	_, err := io.ReadFull(conn, lenBuf)
	if err != nil {
		return nil, err
	}
	idLen := binary.BigEndian.Uint32(lenBuf)

	// Читаем идентификатор сессии
	idBuf := make([]byte, idLen)
	_, err = io.ReadFull(conn, idBuf)
	if err != nil {
		return nil, err
	}

	sessionID, err := uuid.Parse(string(idBuf))
	if err != nil {
		return nil, err
	}

	return &sessionID, nil
}

// authInfo реализует credentials.AuthInfo
type authInfo struct {
	sessionID *uuid.UUID
}

func (a *authInfo) AuthType() string {
	return "pq4"
}
