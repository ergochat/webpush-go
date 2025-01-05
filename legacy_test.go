package webpush

import (
	"encoding/json"
	"testing"
)

const (
	legacyKeysJSON = `{"auth":"1F2Auk0iTJKXjJyiPlMu+w==","p256dh":"BJx6rbJEVu/Juf1xNEk6jO3pTxkyNFGqK1r/zw/iiaEnATH736mYYUSDLFRBsSaIK47vLsVmI+cNraliHyl/8WM="}`

	legacyVAPIDPublicKey = `BEkDdNnpEcD8M4mRGOFJWTDJ4GkDI5Xs3vpIOrAaBZKRCVv6V3sB3CFujTFiD6DHda7W8pCyChJDU205otrbCAw`

	legacyVAPIDPrivateKey = `F0RGqNXLeWLINzn7qIcLsF9lSbRSWgjqUVaoWB6zUqY`

	legacyVAPIDKeyAsJSON = `"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF0RGqNXLeWLINzn7\nqIcLsF9lSbRSWgjqUVaoWB6zUqahRANCAARJA3TZ6RHA/DOJkRjhSVkwyeBpAyOV\n7N76SDqwGgWSkQlb+ld7Adwhbo0xYg+gx3Wu1vKQsgoSQ1NtOaLa2wgM\n-----END PRIVATE KEY-----\n"`
)

func TestLegacySubscriptionKeypair(t *testing.T) {
	var keys Keys
	err := json.Unmarshal([]byte(legacyKeysJSON), &keys)
	if err != nil {
		t.Fatal(err)
	}
	var emptyKeys Keys
	if keys.Auth == emptyKeys.Auth {
		t.Fatal("failed to deserialize auth key")
	}
	if keys.P256dh == emptyKeys.P256dh {
		t.Fatal("failed to deserialize p256dh key")
	}
}

func TestLegacyVAPIDParsing(t *testing.T) {
	// test that we can parse the legacy VAPID private key format (raw bytes
	// of the private key as b64) and we get the same keys as the JSON format
	vapidKeys, err := DecodeLegacyVAPIDPrivateKey(legacyVAPIDPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	if vapidKeys.publicKey != legacyVAPIDPublicKey {
		t.Fatal("decoded legacy VAPID private key, but did not recover true public key")
	}

	vapidKeysFromJSON := new(VAPIDKeys)
	if err := json.Unmarshal([]byte(legacyVAPIDKeyAsJSON), vapidKeysFromJSON); err != nil {
		t.Fatal(err)
	}
	if !vapidKeys.privateKey.Equal(vapidKeysFromJSON.privateKey) {
		t.Fatal("decoded legacy VAPID private key, but did not recover true private key")
	}
	if vapidKeys.publicKey != vapidKeysFromJSON.publicKey {
		t.Fatal("unexpected private/public key mismatch")
	}
}
