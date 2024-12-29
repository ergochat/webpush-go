package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const MaxRecordSize uint32 = 4096

var (
	ErrMaxPadExceeded = errors.New("payload has exceeded the maximum length")

	invalidAuthKeyLength = errors.New("invalid auth key length (must be 16)")
)

// saltFunc generates a salt of 16 bytes
var saltFunc = func() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request, in seconds
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDKeys       *VAPIDKeys // VAPID public-private keypair to generate the VAPID Authorization header
	VapidExpiration time.Time  // optional expiration for VAPID JWT token (defaults to now + 12 hours)
}

// Keys represents a subscription's keys (its ECDH public key on the P-256 curve
// and its 16-byte authentication secret).
type Keys struct {
	Auth   [16]byte
	P256dh *ecdh.PublicKey
}

// Equal compares two Keys for equality.
func (k *Keys) Equal(o Keys) bool {
	return k.Auth == o.Auth && k.P256dh.Equal(o.P256dh)
}

var _ json.Marshaler = (*Keys)(nil)
var _ json.Unmarshaler = (*Keys)(nil)

type marshaledKeys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// MarshalJSON implements json.Marshaler, allowing serialization to JSON.
func (k *Keys) MarshalJSON() ([]byte, error) {
	m := marshaledKeys{
		Auth:   base64.RawStdEncoding.EncodeToString(k.Auth[:]),
		P256dh: base64.RawStdEncoding.EncodeToString(k.P256dh.Bytes()),
	}
	return json.Marshal(&m)
}

// MarshalJSON implements json.Unmarshaler, allowing deserialization from JSON.
func (k *Keys) UnmarshalJSON(b []byte) (err error) {
	var m marshaledKeys
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	authBytes, err := decodeSubscriptionKey(m.Auth)
	if err != nil {
		return err
	}
	if len(authBytes) != 16 {
		return fmt.Errorf("invalid auth bytes length %d (must be 16)", len(authBytes))
	}
	copy(k.Auth[:], authBytes)
	rawDHKey, err := decodeSubscriptionKey(m.P256dh)
	if err != nil {
		return err
	}
	k.P256dh, err = ecdh.P256().NewPublicKey(rawDHKey)
	return err
}

// DecodeSubscriptionKeys decodes and validates a base64-encoded pair of subscription keys
// (the authentication secret and ECDH public key).
func DecodeSubscriptionKeys(auth, p256dh string) (keys Keys, err error) {
	authBytes, err := decodeSubscriptionKey(auth)
	if err != nil {
		return
	}
	if len(authBytes) != 16 {
		err = invalidAuthKeyLength
		return
	}
	copy(keys.Auth[:], authBytes)
	dhBytes, err := decodeSubscriptionKey(p256dh)
	if err != nil {
		return
	}
	keys.P256dh, err = ecdh.P256().NewPublicKey(dhBytes)
	if err != nil {
		return
	}
	return
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// SendNotification calls SendNotificationWithContext with default context for backwards-compatibility
func SendNotification(message []byte, s *Subscription, options *Options) (*http.Response, error) {
	return SendNotificationWithContext(context.Background(), message, s, options)
}

// SendNotificationWithContext sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func SendNotificationWithContext(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {
	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	// Create the ecdh_secret shared key pair

	// Application server key pairs (single use)
	localPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	localPublicKey := localPrivateKey.PublicKey()

	// Combine application keys with receiver's EC public key to derive ECDH shared secret
	sharedECDHSecret, err := localPrivateKey.ECDH(s.Keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}

	hash := sha256.New

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(s.Keys.P256dh.Bytes())
	prkInfoBuf.Write(localPublicKey.Bytes())

	prkHKDF := hkdf.New(hash, sharedECDHSecret, s.Keys.Auth[:], prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Get the record size
	recordSize := options.RecordSize
	if recordSize == 0 {
		recordSize = MaxRecordSize
	}

	recordLength := int(recordSize) - 16

	// Encryption Content-Coding Header
	recordBuf := bytes.NewBuffer(salt)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, recordSize)

	recordBuf.Write(rs)
	recordBuf.Write([]byte{byte(len(localPublicKey.Bytes()))})
	recordBuf.Write(localPublicKey.Bytes())

	// Data
	dataBuf := bytes.NewBuffer(message)

	// Pad content to max record size - 16 - header
	// Padding ending delimeter
	dataBuf.Write([]byte("\x02"))
	if err := pad(dataBuf, recordLength-recordBuf.Len()); err != nil {
		return nil, err
	}

	// Compose the ciphertext
	ciphertext := gcm.Seal([]byte{}, nonce, dataBuf.Bytes(), nil)
	recordBuf.Write(ciphertext)

	// POST request
	req, err := http.NewRequest("POST", s.Endpoint, recordBuf)
	if err != nil {
		return nil, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Сheck the optional headers
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	expiration := options.VapidExpiration
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}

	// Get VAPID Authorization header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		options.Subscriber,
		options.VAPIDKeys,
		expiration,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", vapidAuthHeader)

	// Send the request
	var client HTTPClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	} else {
		client = &http.Client{}
	}

	return client.Do(req)
}

// decodeSubscriptionKey decodes a base64 subscription key.
func decodeSubscriptionKey(key string) ([]byte, error) {
	key = strings.TrimRight(key, "=")

	if strings.IndexByte(key, '+') != -1 || strings.IndexByte(key, '/') != -1 {
		return base64.RawStdEncoding.DecodeString(key)
	}
	return base64.RawURLEncoding.DecodeString(key)
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}

func pad(payload *bytes.Buffer, maxPadLen int) error {
	payloadLen := payload.Len()
	if payloadLen > maxPadLen {
		return ErrMaxPadExceeded
	}

	padLen := maxPadLen - payloadLen

	padding := make([]byte, padLen)
	payload.Write(padding)

	return nil
}
