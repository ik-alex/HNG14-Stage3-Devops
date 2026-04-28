package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the anomaly detection engine.
type Config struct {
	LogFile string `yaml:"log_file"`

	SlidingWindowSeconds int `yaml:"sliding_window_seconds"`

	BaselineWindowMinutes       int     `yaml:"baseline_window_minutes"`
	BaselineRecalcIntervalSecs  int     `yaml:"baseline_recalc_interval_seconds"`
	BaselineFloorMean           float64 `yaml:"baseline_floor_mean"`
	BaselineFloorStddev         float64 `yaml:"baseline_floor_stddev"`
	BaselineMinSamples          int     `yaml:"baseline_min_samples"`

	ZScoreThreshold              float64 `yaml:"zscore_threshold"`
	RateMultiplierThreshold      float64 `yaml:"rate_multiplier_threshold"`
	ErrorRateMultiplier          float64 `yaml:"error_rate_multiplier"`
	ErrorThresholdTighteningFactor float64 `yaml:"error_threshold_tightening_factor"`

	BanDurationsMinutes []int `yaml:"ban_durations_minutes"`

	SlackWebhookURL string `yaml:"slack_webhook_url"`

	DashboardHost           string `yaml:"dashboard_host"`
	DashboardPort           int    `yaml:"dashboard_port"`
	DashboardRefreshSeconds int    `yaml:"dashboard_refresh_seconds"`

	AuditLogFile string `yaml:"audit_log_file"`

	WhitelistIPs []string `yaml:"whitelist_ips"`
}

// LoadConfig reads and parses the YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Override slack webhook from env if set
	if envURL := os.Getenv("SLACK_WEBHOOK_URL"); envURL != "" {
		cfg.SlackWebhookURL = envURL
	}

	return cfg, nil
}