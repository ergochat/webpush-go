package webpush

import (
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
		t.Fatalf("Error is nil, expected=%s", ErrMaxPadExceeded)
	}
}
