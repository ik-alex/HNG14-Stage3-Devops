package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// SlackNotifier sends alerts via Slack incoming webhooks.
type SlackNotifier struct {
	webhookURL string
	enabled    bool
	client     *http.Client
}

// NewSlackNotifier creates a new notifier from config.
func NewSlackNotifier(cfg *Config) *SlackNotifier {
	url := cfg.SlackWebhookURL
	enabled := url != "" && !strings.Contains(url, "YOUR")

	if !enabled {
		log.Println("[notifier] Slack webhook not configured — alerts logged only")
	}

	return &SlackNotifier{
		webhookURL: url,
		enabled:    enabled,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// send posts a payload to the Slack webhook.
func (s *SlackNotifier) send(payload map[string]interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[notifier] Failed to marshal payload: %v", err)
		return
	}

	if !s.enabled {
		log.Printf("[notifier] [DRY-RUN] %s", string(data))
		return
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[notifier] Slack request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[notifier] Slack returned status %d", resp.StatusCode)
	}
}

// SendBanAlert sends a ban notification.
func (s *SlackNotifier) SendBanAlert(ip string, anomaly *AnomalyInfo, ban *BanInfo) {
	durStr := "PERMANENT"
	if ban.DurationMinutes > 0 {
		durStr = fmt.Sprintf("%d minutes", ban.DurationMinutes)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	payload := map[string]interface{}{
		"text": fmt.Sprintf(":rotating_light: *IP BANNED* — `%s`", ip),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": "IP Banned"},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*IP:*\n`%s`", ip)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Condition:*\n%s", anomaly.Condition)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Current Rate:*\n%.2f req/s", anomaly.Rate)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Baseline:*\n%.2f req/s", anomaly.BaselineMean)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Ban Duration:*\n%s", durStr)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Ban Count:*\n#%d", ban.BanCount)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Timestamp:*\n%s", timestamp)},
				},
			},
		},
	}

	log.Printf("[notifier] Sending ban alert for %s", ip)
	s.send(payload)
}

// SendUnbanAlert sends an unban notification.
func (s *SlackNotifier) SendUnbanAlert(ip string, ban *BanInfo) {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	payload := map[string]interface{}{
		"text": fmt.Sprintf(":white_check_mark: *IP UNBANNED* — `%s`", ip),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": "IP Unbanned"},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*IP:*\n`%s`", ip)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Was Banned For:*\n%d minutes", ban.DurationMinutes)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Ban Count:*\n#%d", ban.BanCount)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Original Condition:*\n%s", ban.Condition)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Timestamp:*\n%s", timestamp)},
				},
			},
		},
	}

	log.Printf("[notifier] Sending unban alert for %s", ip)
	s.send(payload)
}

// SendGlobalAnomalyAlert sends a global traffic anomaly alert.
func (s *SlackNotifier) SendGlobalAnomalyAlert(anomaly *AnomalyInfo) {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	payload := map[string]interface{}{
		"text": ":warning: *GLOBAL TRAFFIC ANOMALY DETECTED*",
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": "Global Traffic Anomaly"},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Condition:*\n%s", anomaly.Condition)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Current Rate:*\n%.2f req/s", anomaly.Rate)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Baseline Mean:*\n%.2f req/s", anomaly.BaselineMean)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Baseline StdDev:*\n%.2f", anomaly.BaselineStddev)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Timestamp:*\n%s", timestamp)},
				},
			},
		},
	}

	log.Printf("[notifier] Sending global anomaly alert")
	s.send(payload)
}