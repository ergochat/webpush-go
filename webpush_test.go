package webpush

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type testHTTPClient struct{}

func (*testHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 201}, nil
}

func getURLEncodedTestSubscription() *Subscription {
	subJson := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ"
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJson), sub); err != nil {
		panic(err)
	}
	return sub
}

func getStandardEncodedTestSubscription() *Subscription {
	subJson := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ=="
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJson), sub); err != nil {
		panic(err)
	}
	return sub
}

func TestSendNotificationToURLEncodedSubscription(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification([]byte("Test"), getURLEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		RecordSize: 3070,
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorrect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification([]byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	_, err := SendNotification([]byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
	})
	if err == nil {
		t.Fatalf("Error is nil, expected=%s", ErrRecordSizeTooSmall)
	}
}

func BenchmarkWebPush(b *testing.B) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	message := []byte("@time=2024-12-26T19:36:21.923Z;account=shivaram;msgid=56g9v3b92q6q4wtq43uhyqzegw :shivaram!~u@kca7nfgniet7q.irc PRIVMSG #redacted :[redacted message contents]")
	sub := getStandardEncodedTestSubscription()
	options := Options{
		HTTPClient: &testHTTPClient{},
		RecordSize: 2048,
		Subscriber: "https://example.com",
		TTL:        60 * 60 * 24,
		Urgency:    UrgencyHigh,
		VAPIDKeys:  vapidKeys,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SendNotificationWithContext(ctx, message, sub, &options); err != nil {
			b.Fatal(err)
		}
	}
}
