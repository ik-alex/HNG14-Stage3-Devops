package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// SlidingWindow tracks timestamps of events over the last N seconds
// using a slice-based deque with left eviction.
type SlidingWindow struct {
	windowSeconds int
	events        []float64
}

// NewSlidingWindow creates a sliding window of the given duration.
func NewSlidingWindow(seconds int) *SlidingWindow {
	return &SlidingWindow{
		windowSeconds: seconds,
		events:        make([]float64, 0, 1024),
	}
}

// Add records an event at the given timestamp and evicts old entries.
func (sw *SlidingWindow) Add(timestamp float64) {
	sw.events = append(sw.events, timestamp)
	sw.evict(timestamp)
}

// evict removes entries older than the window from the left.
func (sw *SlidingWindow) evict(now float64) {
	cutoff := now - float64(sw.windowSeconds)
	i := 0
	for i < len(sw.events) && sw.events[i] < cutoff {
		i++
	}
	if i > 0 {
		sw.events = sw.events[i:]
	}
}

// Count returns the number of events in the current window.
func (sw *SlidingWindow) Count(now float64) int {
	sw.evict(now)
	return len(sw.events)
}

// Rate returns events per second over the window.
func (sw *SlidingWindow) Rate(now float64) float64 {
	sw.evict(now)
	if len(sw.events) == 0 {
		return 0
	}
	return float64(len(sw.events)) / float64(sw.windowSeconds)
}

// AnomalyInfo describes a detected anomaly.
type AnomalyInfo struct {
	Type           string  // "ip" or "global"
	IP             string
	Condition      string
	Rate           float64
	BaselineMean   float64
	BaselineStddev float64
}

// IPRateInfo holds rate data for a single IP (for dashboard).
type IPRateInfo struct {
	IP   string  `json:"ip"`
	Rate float64 `json:"rate"`
}

// DetectorStats holds current detector stats for the dashboard.
type DetectorStats struct {
	GlobalRate float64      `json:"global_rate"`
	TopIPs     []IPRateInfo `json:"top_ips"`
	TrackedIPs int          `json:"tracked_ips"`
}

// AnomalyDetector tracks request rates using sliding windows and
// detects anomalies based on z-score or rate multiplier thresholds.
type AnomalyDetector struct {
	mu sync.Mutex

	windowSeconds     int
	zscoreThreshold   float64
	rateMultiplier    float64
	errorMultiplier   float64
	errorTightening   float64
	whitelist         map[string]bool

	baseline *BaselineCalculator

	// Per-IP sliding windows
	ipWindows      map[string]*SlidingWindow
	ipErrorWindows map[string]*SlidingWindow

	// Global sliding window
	globalWindow *SlidingWindow

	// Per-second counters for baseline feeding
	currentSecond    int64
	secondCount      int
	secondErrorCount int
}

// NewAnomalyDetector creates a new detector from config.
func NewAnomalyDetector(cfg *Config, baseline *BaselineCalculator) *AnomalyDetector {
	wl := make(map[string]bool)
	for _, ip := range cfg.WhitelistIPs {
		wl[ip] = true
	}

	return &AnomalyDetector{
		windowSeconds:   cfg.SlidingWindowSeconds,
		zscoreThreshold: cfg.ZScoreThreshold,
		rateMultiplier:  cfg.RateMultiplierThreshold,
		errorMultiplier: cfg.ErrorRateMultiplier,
		errorTightening: cfg.ErrorThresholdTighteningFactor,
		whitelist:       wl,
		baseline:        baseline,
		ipWindows:       make(map[string]*SlidingWindow),
		ipErrorWindows:  make(map[string]*SlidingWindow),
		globalWindow:    NewSlidingWindow(cfg.SlidingWindowSeconds),
	}
}

// RecordRequest records a single request and updates all windows.
func (d *AnomalyDetector) RecordRequest(sourceIP string, status int) {
	now := float64(time.Now().Unix())
	isError := status >= 400

	d.mu.Lock()
	defer d.mu.Unlock()

	d.globalWindow.Add(now)

	if _, ok := d.ipWindows[sourceIP]; !ok {
		d.ipWindows[sourceIP] = NewSlidingWindow(d.windowSeconds)
	}
	d.ipWindows[sourceIP].Add(now)

	if isError {
		if _, ok := d.ipErrorWindows[sourceIP]; !ok {
			d.ipErrorWindows[sourceIP] = NewSlidingWindow(d.windowSeconds)
		}
		d.ipErrorWindows[sourceIP].Add(now)
	}

	// Feed per-second counts to baseline
	currentSec := int64(now)
	if currentSec != d.currentSecond {
		if d.currentSecond > 0 {
			d.baseline.AddSecondCount(
				float64(d.currentSecond),
				d.secondCount,
				d.secondErrorCount,
			)
		}
		d.currentSecond = currentSec
		d.secondCount = 0
		d.secondErrorCount = 0
	}

	d.secondCount++
	if isError {
		d.secondErrorCount++
	}
}

// CheckIPAnomaly checks if a specific IP is anomalous.
func (d *AnomalyDetector) CheckIPAnomaly(sourceIP string) *AnomalyInfo {
	if d.whitelist[sourceIP] {
		return nil
	}

	now := float64(time.Now().Unix())
	mean, stddev := d.baseline.GetBaseline()

	d.mu.Lock()
	var ipRate, ipErrorRate float64
	if w, ok := d.ipWindows[sourceIP]; ok {
		ipRate = w.Rate(now)
	}
	if w, ok := d.ipErrorWindows[sourceIP]; ok {
		ipErrorRate = w.Rate(now)
	}
	d.mu.Unlock()

	// Check error surge — tighten thresholds
	errorBaseline := d.baseline.GetErrorBaseline()
	effectiveZScore := d.zscoreThreshold
	effectiveRateMult := d.rateMultiplier
	conditionExtra := ""

	if errorBaseline > 0 && ipErrorRate > (errorBaseline*d.errorMultiplier) {
		effectiveZScore *= d.errorTightening
		effectiveRateMult *= d.errorTightening
		conditionExtra = " (error-surge-tightened)"
	}

	// Z-score check
	var zscore float64
	if stddev > 0 {
		zscore = (ipRate - mean) / stddev
	} else if ipRate > mean {
		zscore = math.Inf(1)
	}

	if zscore > effectiveZScore {
		return &AnomalyInfo{
			Type:           "ip",
			IP:             sourceIP,
			Condition:      fmt.Sprintf("z-score %.2f > %.1f%s", zscore, effectiveZScore, conditionExtra),
			Rate:           math.Round(ipRate*100) / 100,
			BaselineMean:   math.Round(mean*100) / 100,
			BaselineStddev: math.Round(stddev*100) / 100,
		}
	}

	// Rate multiplier check
	if mean > 0 && ipRate > (mean*effectiveRateMult) {
		return &AnomalyInfo{
			Type:           "ip",
			IP:             sourceIP,
			Condition:      fmt.Sprintf("rate %.2f > %.1fx baseline (%.2f)%s", ipRate, effectiveRateMult, mean, conditionExtra),
			Rate:           math.Round(ipRate*100) / 100,
			BaselineMean:   math.Round(mean*100) / 100,
			BaselineStddev: math.Round(stddev*100) / 100,
		}
	}

	return nil
}

// CheckGlobalAnomaly checks if global traffic rate is anomalous.
func (d *AnomalyDetector) CheckGlobalAnomaly() *AnomalyInfo {
	now := float64(time.Now().Unix())
	mean, stddev := d.baseline.GetBaseline()

	d.mu.Lock()
	globalRate := d.globalWindow.Rate(now)
	d.mu.Unlock()

	var zscore float64
	if stddev > 0 {
		zscore = (globalRate - mean) / stddev
	} else if globalRate > mean {
		zscore = math.Inf(1)
	}

	if zscore > d.zscoreThreshold {
		return &AnomalyInfo{
			Type:           "global",
			IP:             "-",
			Condition:      fmt.Sprintf("global z-score %.2f > %.1f", zscore, d.zscoreThreshold),
			Rate:           math.Round(globalRate*100) / 100,
			BaselineMean:   math.Round(mean*100) / 100,
			BaselineStddev: math.Round(stddev*100) / 100,
		}
	}

	if mean > 0 && globalRate > (mean*d.rateMultiplier) {
		return &AnomalyInfo{
			Type:           "global",
			IP:             "-",
			Condition:      fmt.Sprintf("global rate %.2f > %.1fx baseline (%.2f)", globalRate, d.rateMultiplier, mean),
			Rate:           math.Round(globalRate*100) / 100,
			BaselineMean:   math.Round(mean*100) / 100,
			BaselineStddev: math.Round(stddev*100) / 100,
		}
	}

	return nil
}

// GetStats returns current detector stats for the dashboard.
func (d *AnomalyDetector) GetStats() DetectorStats {
	now := float64(time.Now().Unix())

	d.mu.Lock()
	globalRate := d.globalWindow.Rate(now)

	var ipRates []IPRateInfo
	for ip, w := range d.ipWindows {
		rate := w.Rate(now)
		if rate > 0 {
			ipRates = append(ipRates, IPRateInfo{IP: ip, Rate: math.Round(rate*100) / 100})
		}
	}
	trackedIPs := len(d.ipWindows)
	d.mu.Unlock()

	// Sort top IPs by rate descending
	for i := 0; i < len(ipRates); i++ {
		for j := i + 1; j < len(ipRates); j++ {
			if ipRates[j].Rate > ipRates[i].Rate {
				ipRates[i], ipRates[j] = ipRates[j], ipRates[i]
			}
		}
	}

	top := ipRates
	if len(top) > 10 {
		top = top[:10]
	}

	return DetectorStats{
		GlobalRate: math.Round(globalRate*100) / 100,
		TopIPs:     top,
		TrackedIPs: trackedIPs,
	}
}