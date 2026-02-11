package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ibldzn/branch-closer/internal/fincloud"
)

const webhookSecret = "DPT@SP3n"

func VerifyWebhookSignature(payload []byte, signature, secret string) bool {
	// Hitung HMAC-SHA256(payload, secret) -> hex string
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil) // []byte (32 bytes)

	// signature biasanya: "sha256=<hex>"
	receivedHex := strings.TrimPrefix(signature, "sha256=")

	received, err := hex.DecodeString(receivedHex)
	if err != nil {
		return false
	}

	// Constant-time compare (false jika length beda)
	return hmac.Equal(expected, received)
}

func webhookHandler(res http.ResponseWriter, req *http.Request) {
	const maxBody = 1 << 20 // 1MB

	signature := req.Header.Get("X-Hub-Signature-256")

	// Lindungi dari body kegedean (DoS)
	req.Body = http.MaxBytesReader(res, req.Body, maxBody)
	defer req.Body.Close()

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("Failed to read webhook payload: %v\n", err)
		http.Error(res, "failed to read payload", http.StatusBadRequest)
		return
	}

	if !VerifyWebhookSignature(payload, signature, webhookSecret) {
		log.Println("Invalid webhook signature")
		http.Error(res, "invalid signature", http.StatusUnauthorized)
		return
	}

	var jsonBody struct {
		Event    string         `json:"event"`
		DeviceID string         `json:"device_id"`
		Payload  map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(payload, &jsonBody); err != nil {
		log.Printf("Failed to parse webhook JSON: %v\n", err)
		http.Error(res, "invalid JSON", http.StatusBadRequest)
		return
	}

	if jsonBody.DeviceID != "6289656789225@s.whatsapp.net" {
		http.Error(res, "forbidden", http.StatusForbidden)
		return
	}

	if jsonBody.Payload["is_from_me"].(bool) {
		http.Error(res, "ignored", http.StatusOK)
		return
	}

	// msgBody := jsonBody.Payload["body"].(string)
	ctx := context.Background()

	client, err := fincloud.NewClient(fincloud.Config{
		BaseURL: "http://172.22.80.24/fincloud-taspen",
	})
	if err != nil {
		log.Printf("Failed to create fincloud client: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	session, err := client.Login(ctx, fincloud.Credentials{
		Username:   "2107003_Haytsam",
		Password:   "DPT@SP3n",
		LocationID: "000",
		RoleID:     "R-0040",
	})
	if err != nil {
		log.Printf("Failed to log in to fincloud: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	ctx = fincloud.WithFincloudSessionID(ctx, session.ID)

	branches, err := client.GetUnclosedBranches(ctx)
	if err != nil {
		log.Printf("Failed to get unclosed branches: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	msg := strings.Builder{}
	fmt.Fprintf(&msg, "Closing %d branches:", len(branches))

	for _, branch := range branches {
		fmt.Fprintf(&msg, "\n- %s (%s): ", branch.Name, branch.ID)

		if err := client.CloseBranch(ctx, branch.ID, branch.Name); err != nil {
			// check if the error is an APIError and print details
			var apiErr *fincloud.APIError
			if errors.As(err, &apiErr) {
				msg.WriteString("failed")
				if apiErr.Detail != nil {
					msg.WriteString(" (")
					details := slices.Collect(maps.Values(apiErr.Detail))
					for i, detail := range details {
						if i > 0 {
							msg.WriteString(", ")
						}
						fmt.Fprintf(&msg, "%v", detail)
					}
					msg.WriteString(")")
				}
			} else {
				fmt.Fprintf(&msg, "failed (%v)", err)
			}
			continue
		}

		fmt.Fprintf(&msg, "success")
	}

	fmt.Println(msg.String())

	reqData := struct {
		Message string `json:"message"`
		Phone   string `json:"phone"`
	}{
		Message: msg.String(),
		Phone:   "628976458343@s.whatsapp.net",
	}

	encodedReqData, err := json.Marshal(reqData)
	if err != nil {
		log.Printf("Failed to marshal request data: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	req, err = http.NewRequestWithContext(ctx, "POST", "http://10.66.77.50:3030/send/message", strings.NewReader(string(encodedReqData)))
	if err != nil {
		log.Printf("Failed to create HTTP request: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-Id", "6d561f43-e9e2-45d2-859e-2b7772d60b26")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to send HTTP request: %v\n", err)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code: %d\n", resp.StatusCode)
		http.Error(res, "internal error", http.StatusInternalServerError)
		return
	}

	// Process the valid webhook payload
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("Webhook received and verified"))
}

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	startAddr := ":8989"
	log.Printf("Starting webhook server on %s\n", startAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", webhookHandler)

	srv := http.Server{
		Addr:         startAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v\n", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down webhook server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Failed to shut down server: %v\n", err)
	}

	srv.Shutdown(context.Background())
	log.Println("Webhook server stopped.")
}
