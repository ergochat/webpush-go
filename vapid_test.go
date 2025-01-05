package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestVAPID(t *testing.T) {
	s := getStandardEncodedTestSubscription()
	sub := "test@test.com"

	// Generate vapid keys
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Get authentication header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		sub,
		vapidKeys,
		time.Now().Add(time.Hour*12),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Validate the token in the Authorization header
	tokenString := getTokenFromAuthorizationHeader(vapidAuthHeader, t)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatal("Wrong validation method need ECDSA!")
		}

		// To decode the token it needs the VAPID public key
		return vapidKeys.privateKey.Public(), nil
	})

	// Check the claims on the token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expectedSub := fmt.Sprintf("mailto:%s", sub)
		if expectedSub != claims["sub"] {
			t.Fatalf(
				"Incorreect mailto, expected=%s, got=%s",
				expectedSub,
				claims["sub"],
			)
		}

		if claims["aud"] == "" {
			t.Fatal("Audience should not be empty")
		}
	} else {
		t.Fatal(err)
	}

}

func TestVAPIDKeys(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	j, err := json.Marshal(vapidKeys)
	if err != nil {
		t.Fatal(err)
	}

	vapidKeys2 := new(VAPIDKeys)
	if err := json.Unmarshal(j, vapidKeys2); err != nil {
		t.Fatal(err)
	}

	if !vapidKeys.privateKey.Equal(vapidKeys2.privateKey) {
		t.Fatalf("could not round-trip private key")
	}

	if vapidKeys.publicKey != vapidKeys2.publicKey {
		t.Fatalf("could not round-trip public key")
	}
}

// Helper function for extracting the token from the Authorization header
func getTokenFromAuthorizationHeader(tokenHeader string, t *testing.T) string {
	hsplit := strings.Split(tokenHeader, " ")
	if len(hsplit) < 3 {
		t.Fatal("Failed to auth split header")
	}

	tsplit := strings.Split(hsplit[1], "=")
	if len(tsplit) < 2 {
		t.Fatal("Failed to t split header on =")
	}

	return tsplit[1][:len(tsplit[1])-1]
}

func Test_ecdhPublicKeyToECDSA(t *testing.T) {
	tests := [...]struct {
		name  string
		curve elliptic.Curve
	}{
		// P224 not supported by ecdh
		{
			name:  "P256",
			curve: elliptic.P256(),
		},
		{
			name:  "P256",
			curve: elliptic.P384(),
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating ecdsa.PrivateKey: %s", err)
			}
			original := &pk.PublicKey
			converted, err := original.ECDH()
			if err != nil {
				t.Fatalf("converting ecdsa.PublicKey to ecdh.PublicKey: %s", err)
			}
			roundtrip, err := ecdhPublicKeyToECDSA(converted)
			if err != nil {
				t.Fatalf("converting ecdh.PublicKey back to ecdsa.PublicKey: %s", err)
			}
			if !roundtrip.Equal(original) {
				t.Errorf("Roundtrip changed key from %v to %v", original, roundtrip)
			}
		})
	}
}

func Test_ecdhPrivateKeyToECDSA(t *testing.T) {
	tests := [...]struct {
		name  string
		curve elliptic.Curve
	}{
		// P224 not supported by ecdh
		{
			name:  "P256",
			curve: elliptic.P256(),
		},
		{
			name:  "P256",
			curve: elliptic.P384(),
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating ecdsa.PrivateKey: %s", err)
			}
			converted, err := original.ECDH()
			if err != nil {
				t.Fatalf("converting ecdsa.PrivateKey to ecdh.PrivateKey: %s", err)
			}
			roundtrip, err := ecdhPrivateKeyToECDSA(converted)
			if err != nil {
				t.Fatalf("converting ecdh.PrivateKey back to ecdsa.PrivateKey: %s", err)
			}
			if !roundtrip.Equal(original) {
				t.Errorf("Roundtrip changed key from %v to %v", original, roundtrip)
			}
		})
	}
}

func TestVAPIDKeyFromECDSA(t *testing.T) {
	v, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	privKey := v.PrivateKey()
	v2, err := ECDSAToVAPIDKeys(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Equal(v2) {
		t.Fatal("ECDSAToVAPIDKeys failed round-trip")
	}
}

func BenchmarkVAPIDSigning(b *testing.B) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		b.Fatal(err)
	}
	expiration := time.Now().Add(24 * time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getVAPIDAuthorizationHeader(
			"https://test.push.service/v2/AOWJIDuOMDSo6uNnRXYNsw",
			"https://application.server",
			vapidKeys,
			expiration,
		)
	}
}
