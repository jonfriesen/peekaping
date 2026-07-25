package providers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"peekaping/internal/modules/heartbeat"
	"peekaping/internal/modules/monitor"

	"go.uber.org/zap"
)

// captureWebhook starts a test server that records the first request's body and headers,
// then runs Send against it with the given config fragment. contentType/secret/customBody
// are interpolated into a webhook config JSON pointing at the test server.
func captureWebhook(t *testing.T, contentType, secret, customBody string) (body []byte, headers http.Header) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		headers = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(zap.NewNop().Sugar())
	cfg := fmt.Sprintf(`{
		"webhook_url": %q,
		"webhook_content_type": %q,
		"webhook_custom_body": %q,
		"webhook_signing_secret": %q
	}`, srv.URL, contentType, customBody, secret)

	err := sender.Send(
		context.Background(),
		cfg,
		"test message",
		&monitor.Model{ID: "m1", Name: "Test Monitor"},
		&heartbeat.Model{Msg: "down"},
	)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	return body, headers
}

// Well-known HMAC-SHA256 test vector:
// HMAC-SHA256("The quick brown fox jumps over the lazy dog", key="key")
// pins the algorithm (SHA-256), encoding (lowercase hex), and inputs (body, secret).
func TestSignBody_KnownVector(t *testing.T) {
	got := signBody([]byte("The quick brown fox jumps over the lazy dog"), "key")
	want := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Errorf("signBody = %q, want %q", got, want)
	}
}

// reconstructSignature rebuilds the expected V2 signature the way a receiver would:
// HMAC-SHA256 over "{timestamp}.{body}" using the shared secret.
func reconstructSignature(headers http.Header, body []byte, secret string) string {
	ts := headers.Get(webhookTimestampHeader)
	return signBody([]byte(ts+"."+string(body)), secret)
}

// Pins the V2 signed-payload construction: HMAC over "{timestamp}.{body}",
// dot-delimited, timestamp first. Independent of the live clock.
func TestSignWebhookPayload_JoinsTimestampDotBody(t *testing.T) {
	got := signWebhookPayload("1700000000", []byte("hello"), "key")
	want := signBody([]byte("1700000000.hello"), "key")
	if got != want {
		t.Errorf("signWebhookPayload = %q, want %q (HMAC of \"1700000000.hello\")", got, want)
	}
}

func TestWebhookSend_SignsTimestampDotBody(t *testing.T) {
	body, headers := captureWebhook(t, "json", "shh", "")

	got := headers.Get(webhookSignatureHeader)
	if got == "" {
		t.Fatalf("expected signature on header %q, got none", webhookSignatureHeader)
	}
	want := reconstructSignature(headers, body, "shh")
	if got != want {
		t.Errorf("signature = %q, want %q (HMAC of {timestamp}.{body})", got, want)
	}
}

func TestWebhookSend_SendsRecentTimestamp(t *testing.T) {
	before := time.Now().Unix()
	_, headers := captureWebhook(t, "json", "shh", "")
	after := time.Now().Unix()

	raw := headers.Get(webhookTimestampHeader)
	if raw == "" {
		t.Fatalf("expected %q header when signing, got none", webhookTimestampHeader)
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatalf("timestamp %q is not a unix integer: %v", raw, err)
	}
	if ts < before || ts > after {
		t.Errorf("timestamp %d outside send window [%d, %d]", ts, before, after)
	}
}

func TestWebhookSend_NoSecretNoSignatureOrTimestamp(t *testing.T) {
	_, headers := captureWebhook(t, "json", "", "")

	if got := headers.Get(webhookSignatureHeader); got != "" {
		t.Errorf("expected no signature header without a secret, got %q", got)
	}
	if got := headers.Get(webhookTimestampHeader); got != "" {
		t.Errorf("expected no timestamp header without a secret, got %q", got)
	}
}

// Signing must cover the exact bytes sent for every content type.
func TestWebhookSend_SignsAllContentTypes(t *testing.T) {
	cases := []struct {
		contentType string
		customBody  string
	}{
		{"json", ""},
		{"form-data", ""},
		{"custom", "monitor {{ monitor.name }} is {{ heartbeat.msg }}"},
	}
	for _, tc := range cases {
		t.Run(tc.contentType, func(t *testing.T) {
			body, headers := captureWebhook(t, tc.contentType, "shh", tc.customBody)
			got := headers.Get(webhookSignatureHeader)
			want := reconstructSignature(headers, body, "shh")
			if got != want {
				t.Errorf("signature = %q, want %q (HMAC of {timestamp}.{%s body})", got, want, tc.contentType)
			}
		})
	}
}
