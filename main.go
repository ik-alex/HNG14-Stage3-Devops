package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// AuditLogger writes structured log entries for bans, unbans, and baseline recalculations.
type AuditLogger struct {
	mu       sync.Mutex
	filepath string
}

func NewAuditLogger(path string) *AuditLogger {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	return &AuditLogger{filepath: path}
}

func (a *AuditLogger) Log(action, ip, condition string, rate, baseline float64, duration string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] %s %s | condition: %s | rate: %.2f | baseline: %.2f | duration: %s\n",
		timestamp, action, ip, condition, rate, baseline, duration)

	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[audit] Failed to open audit log: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(entry)

	log.Printf("[audit] %s", entry[:len(entry)-1])
}

func main() {
	log.Println("============================================================")
	log.Println("  Anomaly Detection Engine Starting")
	log.Println("============================================================")

	// Load config
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("[main] Config loaded: log_file=%s", cfg.LogFile)

	// Stop channel for graceful shutdown
	stop := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[main] Received signal: %v", sig)
		close(stop)
	}()

	// Initialize components
	audit := NewAuditLogger(cfg.AuditLogFile)
	baseline := NewBaselineCalculator(cfg)
	baseline.AuditCallback = audit.Log

	detector := NewAnomalyDetector(cfg, baseline)
	blocker := NewIPBlocker(cfg)
	notifier := NewSlackNotifier(cfg)

	unbanner := NewUnbanner(blocker, notifier)
	unbanner.auditCallback = audit.Log

	dashboard := NewDashboardServer(cfg, detector, blocker, baseline)

	// Start log monitor
	logChan := make(chan *LogEntry, 10000)
	go TailLog(cfg.LogFile, logChan, stop)

	// Start unbanner
	go unbanner.Run(stop)

	// Start dashboard
	go dashboard.Start()

	log.Println("[main] All components started")
	log.Printf("[main] Dashboard: http://%s:%d", cfg.DashboardHost, cfg.DashboardPort)
	log.Printf("[main] Monitoring: %s", cfg.LogFile)

	// Main processing loop
	lastGlobalAlert := time.Time{}
	globalAlertCooldown := 60 * time.Second
	processedCount := 0

	for {
		select {
		case <-stop:
			log.Printf("[main] Shutting down. Total processed: %d", processedCount)
			return

		case entry := <-logChan:
			processedCount++
			if processedCount%1000 == 0 {
				log.Printf("[main] Processed %d log entries", processedCount)
			}

			// Recalculate baseline if needed
			if baseline.ShouldRecalculate() {
				baseline.Recalculate()
			}

			// Record request
			detector.RecordRequest(entry.SourceIP, entry.Status)

			// Check per-IP anomaly
			ipAnomaly := detector.CheckIPAnomaly(entry.SourceIP)
			if ipAnomaly != nil {
				banInfo := blocker.BanIP(
					entry.SourceIP,
					ipAnomaly.Condition,
					ipAnomaly.Rate,
					ipAnomaly.BaselineMean,
				)
				if banInfo != nil {
					notifier.SendBanAlert(entry.SourceIP, ipAnomaly, banInfo)

					durStr := "permanent"
					if banInfo.DurationMinutes > 0 {
						durStr = fmt.Sprintf("%dm", banInfo.DurationMinutes)
					}
					audit.Log("BAN", entry.SourceIP, ipAnomaly.Condition,
						ipAnomaly.Rate, ipAnomaly.BaselineMean, durStr)
				}
			}

			// Check global anomaly (with cooldown)
			now := time.Now()
			if now.Sub(lastGlobalAlert) > globalAlertCooldown {
				globalAnomaly := detector.CheckGlobalAnomaly()
				if globalAnomaly != nil {
					notifier.SendGlobalAnomalyAlert(globalAnomaly)
					audit.Log("GLOBAL_ANOMALY", "-", globalAnomaly.Condition,
						globalAnomaly.Rate, globalAnomaly.BaselineMean, "-")
					lastGlobalAlert = now
				}
			}
		}
	}

	// Suppress unused import warnings
	_ = math.Round
}