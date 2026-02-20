package main

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ibldzn/branch-closer/internal/fincloud"
)

const (
	defaultWebhookSecret   = "DPT@SP3n"
	defaultCommand         = "/tutupcabang"
	defaultAllowedDeviceID = "6281806086562@s.whatsapp.net"
	defaultMaxBodyBytes    = int64(1 << 20) // 1MB

	defaultFincloudBaseURL  = "https://172.20.57.7/fincloud-taspen-web"
	defaultFincloudUsername = "2107003_Haytsam"
	defaultFincloudPassword = "DPT@SP3n"
	defaultFincloudLocation = "000"
	defaultFincloudRole     = "R-0040"

	defaultMessageEndpoint = "http://10.66.77.50:3030/send/message"
	defaultTypingEndpoint  = "http://10.66.77.50:3030/send/chat-presence"
	defaultMessageDeviceID = "ccs"

	defaultServerAddr      = ":8989"
	defaultReadTimeout     = 30 * time.Second
	defaultWriteTimeout    = 30 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 5 * time.Second
	defaultHTTPTimeout     = 15 * time.Second
)

var defaultAllowedSenders = []string{
	"628976458343@s.whatsapp.net", // ADMIN, has to be first
	"6282227896688@s.whatsapp.net",
}

type Config struct {
	WebhookSecret   string
	Command         string
	AllowedDeviceID string
	AllowedSenders  []string
	MaxBodyBytes    int64

	FincloudBaseURL    string
	FincloudCredential fincloud.Credentials

	MessageEndpoint string
	TypingEndpoint  string
	MessageDeviceID string
	MessagePhone    string

	ServerAddr      string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	HTTPTimeout     time.Duration
}

func loadConfig() Config {
	return Config{
		WebhookSecret:   envString("WA_WEBHOOK_SECRET", defaultWebhookSecret),
		Command:         envString("WA_COMMAND", defaultCommand),
		AllowedDeviceID: envString("WA_ALLOWED_DEVICE_ID", defaultAllowedDeviceID),
		AllowedSenders:  defaultAllowedSenders,
		MaxBodyBytes:    envInt64("WA_MAX_BODY_BYTES", defaultMaxBodyBytes),

		FincloudBaseURL: envString("WA_FINCLOUD_BASE_URL", defaultFincloudBaseURL),
		FincloudCredential: fincloud.Credentials{
			Username:   envString("WA_FINCLOUD_USERNAME", defaultFincloudUsername),
			Password:   envString("WA_FINCLOUD_PASSWORD", defaultFincloudPassword),
			LocationID: envString("WA_FINCLOUD_LOCATION_ID", defaultFincloudLocation),
			RoleID:     envString("WA_FINCLOUD_ROLE_ID", defaultFincloudRole),
		},

		MessageEndpoint: envString("WA_MESSAGE_ENDPOINT", defaultMessageEndpoint),
		TypingEndpoint:  envString("WA_TYPING_ENDPOINT", defaultTypingEndpoint),
		MessageDeviceID: envString("WA_MESSAGE_DEVICE_ID", defaultMessageDeviceID),

		ServerAddr:      envString("WA_SERVER_ADDR", defaultServerAddr),
		ReadTimeout:     defaultReadTimeout,
		WriteTimeout:    defaultWriteTimeout,
		IdleTimeout:     defaultIdleTimeout,
		ShutdownTimeout: defaultShutdownTimeout,
		HTTPTimeout:     defaultHTTPTimeout,
	}
}

func envString(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}

	return parsed
}
