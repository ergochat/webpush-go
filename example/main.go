package main

import (
	"context"
	"encoding/json"
	"time"

	webpush "github.com/ergochat/webpush-go/v2"
)

const (
	subscription    = ``
	vapidPrivateKey = ""
)

func main() {
	// Decode subscription
	sub := &webpush.Subscription{}
	json.Unmarshal([]byte(subscription), sub)
	// Decode VAPID keys
	v := &webpush.VAPIDKeys{}
	json.Unmarshal([]byte(vapidPrivateKey), v)

	// Send Notification
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := webpush.SendNotification(
		ctx,
		[]byte("Test"),
		sub,
		&webpush.Options{
			Subscriber: "example@example.com", // Do not include "mailto:"
			VAPIDKeys:  v,
			TTL:        30,
		},
	)
	if err != nil {
		// TODO: Handle error
	}
	defer resp.Body.Close()
}
