package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"
)

const (
	databaseUrl = "postgresql://myuser:mypassword@db:5432/secure_messaging"
	jwtSecret   = "SUPER_SECRET_JWT_SECRET"
)

var conn *pgx.Conn

type User struct {
	ID         int
	Nickname   string
	PublicKey  string
	PrivateKey string
}

type Message struct {
	ID               int
	SenderID         int
	ReceiverID       int
	EncryptedMessage string
	EncryptedAESKey  string
	Status           string
	Expiration       time.Time
}

func main() {
	initCronJob()

	app := fiber.New()

	// Connect to the database
	var err error
	conn, err = pgx.Connect(context.Background(), databaseUrl)
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	defer conn.Close(context.Background())

	// Routes for user registration and login
	app.Post("/register", registerUser)
	app.Post("/login", loginUser)

	app.Get("/messages", getMessages)

	// Middleware to check JWT token
	app.Use(func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		c.Locals("user_id", int(claims["user_id"].(float64)))
		return c.Next()
	})

	// WebSocket endpoint
	app.Get("/ws", websocket.New(func(c *websocket.Conn) {
		userID := c.Locals("user_id").(int)

		for {
			mt, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				break
			}
			log.Printf("recv: %s", message)

			// Handle the incoming message (example format, adjust as needed)
			var msg map[string]string
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Println("error:", err)
				continue
			}

			if err := handleIncomingMessage(userID, msg); err != nil {
				log.Println("error:", err)
			}

			err = c.WriteMessage(mt, []byte("Message processed"))
			if err != nil {
				log.Println("write:", err)
				break
			}
		}
	}))

	log.Fatal(app.Listen(":3000"))
}

// registerUser handles user registration
func registerUser(c *fiber.Ctx) error {
	type request struct {
		Nickname string `json:"nickname"`
	}

	req := new(request)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if req.Nickname == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Nickname is required"})
	}

	// Generate RSA keys
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Key generation failed"})
	}

	// Insert user into the database
	query := "INSERT INTO users (nickname, public_key, private_key) VALUES ($1, $2, $3) RETURNING id"
	row := conn.QueryRow(context.Background(), query, req.Nickname, publicKey, privateKey)
	var userID int
	if err := row.Scan(&userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User registration failed"})
	}

	return c.JSON(fiber.Map{"message": "User registered successfully", "user_id": userID})
}

// loginUser handles user login
func loginUser(c *fiber.Ctx) error {
	type request struct {
		Nickname string `json:"nickname"`
	}

	req := new(request)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Fetch user from database
	query := "SELECT id FROM users WHERE nickname=$1"
	row := conn.QueryRow(context.Background(), query, req.Nickname)
	var userID int
	if err := row.Scan(&userID); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Create JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	t, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{"token": t})
}

// getMessages handles retrieving messages
func getMessages(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)

	messages, err := getMessageHistory(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve messages"})
	}

	return c.JSON(fiber.Map{"messages": messages})
}

// generateKeys generates a pair of RSA keys
func generateKeys() (privateKey string, publicKey string, err error) {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return "", "", err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}))

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyBytes}))

	return privateKey, publicKey, nil
}

// handleIncomingMessage handles an incoming message
func handleIncomingMessage(senderID int, msg map[string]string) error {
	receiverNickname := msg["receiver"]
	messageText := msg["message"]
	expirationDuration := msg["expiration"]

	// Find receiver's public key
	var receiver User
	err := conn.QueryRow(context.Background(), "SELECT id, public_key FROM users WHERE nickname=$1", receiverNickname).Scan(&receiver.ID, &receiver.PublicKey)
	if err != nil {
		return errors.New("receiver not found")
	}

	// Encrypt the message
	aesKey, encryptedMessage, err := encryptMessage(messageText)
	if err != nil {
		return err
	}

	// Encrypt AES key with receiver's public RSA key
	encryptedAESKey, err := encryptAESKey(aesKey, receiver.PublicKey)
	if err != nil {
		return err
	}

	expiration, err := time.ParseDuration(expirationDuration)
	if err != nil {
		return errors.New("invalid expiration format")
	}

	// Store message in the database
	_, err = conn.Exec(context.Background(), "INSERT INTO messages (sender_id, receiver_id, encrypted_message, encrypted_aes_key, status, expiration) VALUES ($1, $2, $3, $4, $5, $6)",
		senderID, receiver.ID, encryptedMessage, encryptedAESKey, "sent", time.Now().Add(expiration))
	if err != nil {
		return err
	}

	return nil
}

// encryptMessage encrypts the message using AES
func encryptMessage(message string) (aesKey, encryptedMessage string, err error) {
	key := make([]byte, 32) // AES-256
	_, err = rand.Read(key)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(ciphertext), nil
}

// encryptAESKey encrypts the AES key using RSA public key
func encryptAESKey(aesKey, publicKey string) (string, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return "", errors.New("failed to parse RSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not a valid RSA public key")
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, []byte(aesKey), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// decryptAESKey decrypts the AES key using RSA private key
func decryptAESKey(encryptedAESKey, privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to parse RSA private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedAESKey)
	if err != nil {
		return "", err
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return "", err
	}

	return string(aesKey), nil
}

// decryptMessage decrypts the message using AES
func decryptMessage(encryptedMessage, aesKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(aesKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// Retrieve and decrypt messages for a user
func getMessageHistory(userID int) ([]Message, error) {
	rows, err := conn.Query(context.Background(), "SELECT id, sender_id, encrypted_message, encrypted_aes_key, status, expiration FROM messages WHERE receiver_id=$1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := []Message{}
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.EncryptedMessage, &msg.EncryptedAESKey, &msg.Status, &msg.Expiration); err != nil {
			return nil, err
		}

		// Decrypt AES key
		var user User
		err := conn.QueryRow(context.Background(), "SELECT private_key FROM users WHERE id=$1", userID).Scan(&user.PrivateKey)
		if err != nil {
			return nil, err
		}

		aesKey, err := decryptAESKey(msg.EncryptedAESKey, user.PrivateKey)
		if err != nil {
			return nil, err
		}

		// Decrypt message
		decryptedMessage, err := decryptMessage(msg.EncryptedMessage, aesKey)
		if err != nil {
			return nil, err
		}

		msg.EncryptedMessage = decryptedMessage
		messages = append(messages, msg)
	}

	return messages, nil
}

// Initialize the cron job
func initCronJob() {
	c := cron.New()
	c.AddFunc("@hourly", func() {
		deleteExpiredMessages()
	})
	c.Start()
}

// deleteExpiredMessages deletes messages that have expired
func deleteExpiredMessages() {
	_, err := conn.Exec(context.Background(), "DELETE FROM messages WHERE expiration < $1", time.Now())
	if err != nil {
		log.Println("Failed to delete expired messages:", err)
	}
}

// Update message status
func updateMessageStatus(messageID int, status string) error {
	_, err := conn.Exec(context.Background(), "UPDATE messages SET status=$1 WHERE id=$2", status, messageID)
	return err
}
