// ssfreceiver/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sgnl-ai/caep.dev/secevent/pkg/event"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/parser"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/caep"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/ssf"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/token"
	"github.com/sgnl-ai/caep.dev/ssfreceiver/auth"
	"github.com/sgnl-ai/caep.dev/ssfreceiver/builder"
)

func main() {
	// ---- config from env
	transmitterWK := "https://api.cacab.ngrok.io/.well-known/ssf-configuration"
	pushEndpoint := "http://localhost:8766/events"
	bearerToken := "<your api token>"

	kolideAPIVer := "2023-05-26"
	kolideAuth := "Bearer <your api token>"

	// ---- auth to talk TO the transmitter (used during stream setup)
	bearerAuth, err := auth.NewBearer(bearerToken)
	if err != nil {
		log.Fatalf("auth.NewBearer: %v", err)
	}

	// Optional: if your metadata/config/status endpoints need custom headers
	// prefer the library’s built-in header options.
	// (See "Endpoint-Specific Headers" options in docs.) :contentReference[oaicite:2]{index=2}
	opts := []builder.Option{
		builder.WithPushDelivery(pushEndpoint),
		builder.WithAuth(bearerAuth),
		builder.WithEventTypes([]event.EventType{
			event.EventType("device_trust.status_changed"),
			ssf.EventTypeVerification,
		}),
		builder.WithExistingCheck(),
	}

	if kolideAPIVer != "" || kolideAuth != "" {
		metaHeaders := map[string]string{}
		if kolideAPIVer != "" {
			metaHeaders["X-Kolide-Api-Version"] = kolideAPIVer
		}
		if kolideAuth != "" {
			metaHeaders["Authorization"] = kolideAuth
		}
		opts = append(opts,
			builder.WithMetadataEndpointHeaders(metaHeaders),
			builder.WithConfigurationEndpointHeaders(metaHeaders),
			builder.WithStatusEndpointHeaders(metaHeaders),
		)
	}

	streamBuilder, err := builder.New(transmitterWK, opts...)
	if err != nil {
		log.Fatalf("builder.New: %v", err)
	}

	// Short context for setup so failures don't hang forever
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("Setting up stream connection to %s ...", transmitterWK)
	stream, err := streamBuilder.Setup(ctx)
	if err != nil {
		log.Fatalf("stream setup failed: %v", err)
	}
	log.Printf("Stream setup completed. Stream ID: %s", stream.GetStreamID())

	// HTTP endpoint to receive push events
	http.HandleFunc("/events", HandlePushedEvent)

	addr := ":8766"
	log.Printf("Receiver listening on http://localhost%s/events", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func HandlePushedEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	body := strings.TrimSpace(string(raw))
	log.Printf("RAW BODY: %q", body)

	jwtStr, err := extractSecEventToken(body, r.Header.Get("Content-Type"))
	if err != nil {
		log.Printf("failed to extract token: %v", err)
		http.Error(w, "bad event", http.StatusBadRequest)
		return
	}

	secEventParser := parser.NewParser()
	secEvent, err := secEventParser.ParseSecEventNoVerify(jwtStr)
	if err != nil {
		log.Printf("parse error: %v", err)
		http.Error(w, "bad event", http.StatusBadRequest)
		return
	}

	switch secEvent.Event.Type() {
	case ssf.EventTypeVerification:
		handleVerification(secEvent)
	case caep.EventTypeSessionRevoked:
		handleSessionRevoked(secEvent)
	default:
		log.Printf("Unhandled event type: %s", secEvent.Event.Type())
	}

	w.WriteHeader(http.StatusOK)
}

func extractSecEventToken(body string, contentType string) (string, error) {
	// JSON string like: "eyJ0eXAiOiJzZWNldmVudCtqd3Qi..."
	if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
		return strconv.Unquote(body)
	}

	// JSON object like: {"secevent":"<jwt>"} or {"token":"<jwt>"}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/json") {
		var v any
		if err := json.Unmarshal([]byte(body), &v); err == nil {
			if s, ok := v.(string); ok {
				return s, nil
			}
			if m, ok := v.(map[string]any); ok {
				for _, k := range []string{"secevent", "event", "token"} {
					if val, ok := m[k].(string); ok && val != "" {
						return val, nil
					}
				}
			}
		}
	}

	// Otherwise assume the body already is the compact JWS (no quotes)
	return body, nil
}

func handleSessionRevoked(secEvent *token.SecEvent) {
	log.Printf("Session revoked: jti=%s", secEvent.ID)
	if sub, err := secEvent.Subject.Payload(); err == nil {
		log.Printf("Subject: %+v", sub)
	}
}

func handleDeviceTrustStatusChanged(secEvent *token.SecEvent) {
	log.Printf("Device trust status changed: jti=%s", secEvent.ID)
	if sub, err := secEvent.Subject.Payload(); err == nil {
		log.Printf("Subject: %+v", sub)
	}
}

func handleVerification(secEvent *token.SecEvent) {
	log.Printf("Verification event: jti=%s", secEvent.ID)
	if v, ok := secEvent.Event.(*ssf.VerificationEvent); ok {
		if state, exist := v.GetState(); exist {
			log.Printf("Verification state: %s", state)
		}
	}
}

func ioReadAll(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func mustGetEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing required env: %s", k)
	}
	return v
}
