package main

import (
	"bytes"
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
	"slices"
	"strings"
	"time"

	"github.com/ibldzn/branch-closer/internal/fincloud"
)

type App struct {
	cfg        Config
	httpClient *http.Client
}

var wibLocation = time.FixedZone("WIB", 7*60*60)

func NewApp(cfg Config) *App {
	return &App{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
	}
}

type webhookEvent struct {
	Event    string         `json:"event"`
	DeviceID string         `json:"device_id"`
	Payload  map[string]any `json:"payload"`
}

func (a *App) webhookHandler(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("OK"))

	status := "ok"

	defer func() {
		log.Printf("Webhook processed with status: %s\n", status)
	}()

	payload, err := readBodyWithLimit(res, req, a.cfg.MaxBodyBytes)
	if err != nil {
		status = "failed to read payload"
		return
	}

	signature := req.Header.Get("X-Hub-Signature-256")
	if !verifyWebhookSignature(payload, signature, a.cfg.WebhookSecret) {
		status = "invalid signature"
		return
	}

	event, err := parseWebhookPayload(payload)
	if err != nil {
		status = "invalid JSON"
		return
	}

	if event.Event != "message" {
		status = "ignored non-message event: " + event.Event
		return
	}

	if event.DeviceID != a.cfg.AllowedDeviceID {
		status = "unauthorized device: " + event.DeviceID
		return
	}

	isFromMe, ok := event.Payload["is_from_me"].(bool)
	if ok && isFromMe {
		status = "ignored own message"
		return
	}

	sender := event.Payload["from"].(string)
	if !slices.Contains(a.cfg.AllowedSenders, sender) {
		status = "unauthorized sender: " + sender
		return
	}

	ctx := req.Context()

	_ = a.sendTypingIndicator(ctx, sender, true)
	defer func() {
		_ = a.sendTypingIndicator(ctx, sender, false)
	}()

	body := strings.TrimSpace(event.Payload["body"].(string))
	if sender == a.cfg.AllowedSenders[0] && body == "ping" {
		_ = a.sendMessage(ctx, sender, "pong")
		status = "responded to ping"
		return
	}

	if body != a.cfg.Command {
		status = "ignored unknown command"
		return
	}

	message, err := a.closeBranches(ctx)
	if err != nil {
		_ = a.sendMessage(ctx, sender, "Error closing branches:\n\n"+err.Error())
		status = "failed to close branches: " + err.Error()
		return
	}

	if err := a.sendMessage(ctx, sender, message); err != nil {
		status = "failed to send message: " + err.Error()
		return
	}
}

func readBodyWithLimit(res http.ResponseWriter, req *http.Request, limit int64) ([]byte, error) {
	req.Body = http.MaxBytesReader(res, req.Body, limit)
	defer req.Body.Close()
	return io.ReadAll(req.Body)
}

func parseWebhookPayload(payload []byte) (webhookEvent, error) {
	var event webhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return webhookEvent{}, err
	}
	return event, nil
}

func verifyWebhookSignature(payload []byte, signature, secret string) bool {
	if signature == "" || secret == "" {
		return false
	}

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

func (a *App) closeBranches(ctx context.Context) (string, error) {
	client, err := fincloud.NewClient(fincloud.Config{
		BaseURL: a.cfg.FincloudBaseURL,
	})
	if err != nil {
		return "", err
	}

	session, err := client.Login(ctx, a.cfg.FincloudCredential)
	if err != nil {
		return "", err
	}

	ctx = fincloud.WithFincloudSessionID(ctx, session.ID)

	branches, err := client.GetUnclosedBranches(ctx)
	if err != nil {
		return "", err
	}

	results := make([]branchCloseResult, 0, len(branches))
	for _, branch := range branches {
		closeErr := client.CloseBranch(ctx, branch.ID, branch.Name)
		results = append(results, branchCloseResult{
			Name: branch.Name,
			ID:   branch.ID,
			Err:  closeErr,
		})
	}

	msg := formatCloseBranchesMessage(results, time.Now().In(wibLocation))
	log.Print(msg)

	return msg, nil
}

type branchCloseResult struct {
	Name string
	ID   string
	Err  error
}

func formatCloseBranchesMessage(results []branchCloseResult, finishedAt time.Time) string {
	successCount := 0
	for _, result := range results {
		if result.Err == nil {
			successCount++
		}
	}

	failedCount := len(results) - successCount

	msg := strings.Builder{}
	msg.WriteString("*Result Close Branch*\n")
	fmt.Fprintf(&msg, "Tanggal: %s\n", finishedAt.Format("02-01-2006"))
	fmt.Fprintf(&msg, "Waktu: %s WIB", finishedAt.Format("15:04:05"))

	if len(results) == 0 {
		msg.WriteString("\n\nTidak ada cabang yang perlu ditutup saat ini.")
	} else {
		fmt.Fprintf(
			&msg,
			"\n\n*Ringkasan*\n- Total cabang: %d\n- Berhasil: %d\n- Gagal: %d",
			len(results),
			successCount,
			failedCount,
		)

		msg.WriteString("\n\n*Details*")
		for i, result := range results {
			fmt.Fprintf(
				&msg,
				"\n%d. %s (%s): %s",
				i+1,
				result.Name,
				result.ID,
				closeResultStatus(result.Err),
			)
		}
	}

	msg.WriteString("\n\n===\n\n_Ini adalah pesan otomatis. Terima kasih._")

	return msg.String()
}

func closeResultStatus(err error) string {
	if err == nil {
		return "berhasil"
	}

	var apiErr *fincloud.APIError
	if !errors.As(err, &apiErr) {
		return fmt.Sprintf("gagal (%v)", err)
	}

	if apiErr.Detail == nil {
		return "gagal"
	}

	msg := strings.Builder{}
	msg.WriteString("gagal (")
	details := slices.Collect(maps.Values(apiErr.Detail))
	for i, detail := range details {
		if i > 0 {
			msg.WriteString(", ")
		}
		fmt.Fprintf(&msg, "%v", detail)
	}
	msg.WriteString(")")

	return msg.String()
}

type messageRequest struct {
	Message string `json:"message"`
	Phone   string `json:"phone"`
}

func (a *App) sendMessage(ctx context.Context, to, message string) error {
	payload, err := json.Marshal(messageRequest{
		Message: message,
		Phone:   to,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.cfg.MessageEndpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-Id", a.cfg.MessageDeviceID)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

type typingIndicatorRequest struct {
	Phone  string `json:"phone"`
	Action string `json:"action"` // "start" atau "stop"
}

func (a *App) sendTypingIndicator(ctx context.Context, to string, state bool) error {
	action := "stop"
	if state {
		action = "start"
	}

	payload, err := json.Marshal(typingIndicatorRequest{
		Phone:  to,
		Action: action,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.cfg.TypingEndpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-Id", a.cfg.MessageDeviceID)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
