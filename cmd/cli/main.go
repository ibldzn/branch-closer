package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/ibldzn/branch-closer/internal/fincloud"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	client, err := fincloud.NewClient(fincloud.Config{
		BaseURL: "http://172.22.80.24/fincloud-taspen",
	})
	if err != nil {
		errorExit("failed to create fincloud client", err)
	}

	session, err := client.Login(ctx, fincloud.Credentials{
		Username:   "2107003_Haytsam",
		Password:   "DPT@SP3n",
		LocationID: "000",
		RoleID:     "R-0040",
	})
	if err != nil {
		errorExit("failed to log in to fincloud", err)
	}

	ctx = fincloud.WithFincloudSessionID(ctx, session.ID)

	branches, err := client.GetUnclosedBranches(ctx)
	if err != nil {
		errorExit("failed to get unclosed branches", err)
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
		errorExit("failed to marshal request data", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "http://10.66.77.50:3030/send/message", strings.NewReader(string(encodedReqData)))
	if err != nil {
		errorExit("failed to create HTTP request", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		errorExit("failed to send HTTP request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorExit(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
}

func errorExit(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
