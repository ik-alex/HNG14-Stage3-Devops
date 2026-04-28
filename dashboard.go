package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DashboardServer serves the live metrics dashboard.
type DashboardServer struct {
	detector  *AnomalyDetector
	blocker   *IPBlocker
	baseline  *BaselineCalculator
	startTime time.Time
	host      string
	port      int
}

// NewDashboardServer creates a new dashboard server.
func NewDashboardServer(cfg *Config, detector *AnomalyDetector, blocker *IPBlocker, baseline *BaselineCalculator) *DashboardServer {
	return &DashboardServer{
		detector:  detector,
		blocker:   blocker,
		baseline:  baseline,
		startTime: time.Now(),
		host:      cfg.DashboardHost,
		port:      cfg.DashboardPort,
	}
}

func (ds *DashboardServer) getSystemStats() (cpuPercent, memPercent float64, memUsedMB, memTotalMB int) {
	// CPU from /proc/stat
	data, err := os.ReadFile("/proc/stat")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 5 {
				var total, idle int64
				for i := 1; i < len(parts); i++ {
					v, _ := strconv.ParseInt(parts[i], 10, 64)
					total += v
					if i == 4 {
						idle = v
					}
				}
				if total > 0 {
					cpuPercent = math.Round((1-float64(idle)/float64(total))*10000) / 100
				}
			}
		}
	}

	// Memory from /proc/meminfo
	data, err = os.ReadFile("/proc/meminfo")
	if err == nil {
		memInfo := make(map[string]int)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.Atoi(parts[1])
				memInfo[key] = val
			}
		}
		memTotalMB = memInfo["MemTotal"] / 1024
		memAvail := memInfo["MemAvailable"] / 1024
		memUsedMB = memTotalMB - memAvail
		if memTotalMB > 0 {
			memPercent = math.Round(float64(memUsedMB)/float64(memTotalMB)*1000) / 10
		}
	}

	return
}

func (ds *DashboardServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(ds.startTime)
	cpu, memPct, memUsed, memTotal := ds.getSystemStats()

	data := map[string]interface{}{
		"uptime":     fmt.Sprintf("%dh %dm %ds", int(uptime.Hours()), int(uptime.Minutes())%60, int(uptime.Seconds())%60),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"system":     map[string]interface{}{"cpu_percent": cpu, "mem_percent": memPct, "mem_used_mb": memUsed, "mem_total_mb": memTotal},
		"detector":   ds.detector.GetStats(),
		"banned_ips": ds.blocker.GetBannedIPs(),
		"baseline":   ds.baseline.GetStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(data)
}

func (ds *DashboardServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(ds.startTime)
	uptimeStr := fmt.Sprintf("%dh %dm %ds", int(uptime.Hours()), int(uptime.Minutes())%60, int(uptime.Seconds())%60)

	cpu, memPct, memUsed, memTotal := ds.getSystemStats()
	detectorStats := ds.detector.GetStats()
	bannedIPs := ds.blocker.GetBannedIPs()
	baselineStats := ds.baseline.GetStats()

	rateClass := "green"
	if detectorStats.GlobalRate > baselineStats.EffectiveMean*3 {
		rateClass = "red"
	}
	banClass := "green"
	if len(bannedIPs) > 0 {
		banClass = "red"
	}

	// Banned IPs table
	bannedTable := `<p style="color:#64748b;">No IPs currently banned</p>`
	if len(bannedIPs) > 0 {
		rows := ""
		for _, b := range bannedIPs {
			rows += fmt.Sprintf(
				"<tr><td>%s</td><td><span class='badge ban'>%s</span></td><td>%.1fm</td><td>%d</td><td>%s</td><td>%.2f</td></tr>",
				b.IP, b.Duration, b.ElapsedMinutes, b.BanCount, b.Condition, b.Rate,
			)
		}
		bannedTable = fmt.Sprintf(
			"<table><tr><th>IP</th><th>Duration</th><th>Elapsed</th><th>Ban #</th><th>Condition</th><th>Rate</th></tr>%s</table>",
			rows,
		)
	}

	// Top IPs table
	topIPsTable := `<p style="color:#64748b;">No traffic recorded yet</p>`
	if len(detectorStats.TopIPs) > 0 {
		rows := ""
		for _, t := range detectorStats.TopIPs {
			rows += fmt.Sprintf("<tr><td>%s</td><td>%.2f req/s</td></tr>", t.IP, t.Rate)
		}
		topIPsTable = fmt.Sprintf("<table><tr><th>IP</th><th>Rate</th></tr>%s</table>", rows)
	}

	// Hourly slots
	hourlyHTML := `<p style="color:#64748b;">No hourly data yet</p>`
	if len(baselineStats.HourlySlotStats) > 0 {
		hours := make([]int, 0, len(baselineStats.HourlySlotStats))
		for h := range baselineStats.HourlySlotStats {
			hours = append(hours, h)
		}
		sort.Ints(hours)
		parts := make([]string, 0, len(hours))
		for _, h := range hours {
			s := baselineStats.HourlySlotStats[h]
			parts = append(parts, fmt.Sprintf("Hour %d: mean=%.2f, samples=%d", h, s.Mean, s.Size))
		}
		hourlyHTML = `<p style="margin-top:8px;">` + strings.Join(parts, "<br>") + "</p>"
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	html := dashboardTemplate
	html = strings.ReplaceAll(html, "{{UPTIME}}", uptimeStr)
	html = strings.ReplaceAll(html, "{{GLOBAL_RATE}}", fmt.Sprintf("%.2f", detectorStats.GlobalRate))
	html = strings.ReplaceAll(html, "{{RATE_CLASS}}", rateClass)
	html = strings.ReplaceAll(html, "{{BANNED_COUNT}}", strconv.Itoa(len(bannedIPs)))
	html = strings.ReplaceAll(html, "{{BAN_CLASS}}", banClass)
	html = strings.ReplaceAll(html, "{{TRACKED_IPS}}", strconv.Itoa(detectorStats.TrackedIPs))
	html = strings.ReplaceAll(html, "{{CPU}}", fmt.Sprintf("%.1f", cpu))
	html = strings.ReplaceAll(html, "{{MEM_USED}}", strconv.Itoa(memUsed))
	html = strings.ReplaceAll(html, "{{MEM_TOTAL}}", strconv.Itoa(memTotal))
	html = strings.ReplaceAll(html, "{{MEM_PCT}}", fmt.Sprintf("%.1f", memPct))
	html = strings.ReplaceAll(html, "{{EFF_MEAN}}", fmt.Sprintf("%.2f", baselineStats.EffectiveMean))
	html = strings.ReplaceAll(html, "{{EFF_STDDEV}}", fmt.Sprintf("%.2f", baselineStats.EffectiveStddev))
	html = strings.ReplaceAll(html, "{{BANNED_TABLE}}", bannedTable)
	html = strings.ReplaceAll(html, "{{TOP_IPS_TABLE}}", topIPsTable)
	html = strings.ReplaceAll(html, "{{RECALC_COUNT}}", strconv.Itoa(baselineStats.RecalcCount))
	html = strings.ReplaceAll(html, "{{SAMPLES}}", strconv.Itoa(baselineStats.Samples))
	html = strings.ReplaceAll(html, "{{HOURLY_SLOTS}}", hourlyHTML)
	html = strings.ReplaceAll(html, "{{TIMESTAMP}}", timestamp)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Start starts the dashboard HTTP server.
func (ds *DashboardServer) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", ds.handleAPI)
	mux.HandleFunc("/", ds.handleDashboard)

	addr := fmt.Sprintf("%s:%d", ds.host, ds.port)
	log.Printf("[dashboard] Running at http://%s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("[dashboard] Server failed: %v", err)
	}
}

const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>Anomaly Detection Dashboard</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
  h1{color:#38bdf8;margin-bottom:20px;font-size:1.8em}
  h2{color:#94a3b8;margin:15px 0 10px;font-size:1.1em;text-transform:uppercase;letter-spacing:1px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;margin-bottom:20px}
  .card{background:#1e293b;border-radius:10px;padding:18px;border:1px solid #334155}
  .card .label{color:#94a3b8;font-size:.85em;margin-bottom:4px}
  .card .value{font-size:1.6em;font-weight:700;color:#f1f5f9}
  .card .value.green{color:#4ade80}.card .value.red{color:#f87171}
  .card .value.yellow{color:#fbbf24}.card .value.blue{color:#38bdf8}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th{text-align:left;padding:8px 12px;background:#334155;color:#94a3b8;font-size:.8em;text-transform:uppercase}
  td{padding:8px 12px;border-bottom:1px solid #334155;font-size:.9em}
  tr:hover{background:#334155}
  .badge{padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:600}
  .badge.ban{background:#7f1d1d;color:#fca5a5}
  .footer{margin-top:20px;color:#64748b;font-size:.8em;text-align:center}
</style>
</head>
<body>
<h1>Anomaly Detection Engine</h1>
<div class="grid">
  <div class="card"><div class="label">Uptime</div><div class="value blue">{{UPTIME}}</div></div>
  <div class="card"><div class="label">Global Req/s</div><div class="value {{RATE_CLASS}}">{{GLOBAL_RATE}}</div></div>
  <div class="card"><div class="label">Banned IPs</div><div class="value {{BAN_CLASS}}">{{BANNED_COUNT}}</div></div>
  <div class="card"><div class="label">Tracked IPs</div><div class="value">{{TRACKED_IPS}}</div></div>
  <div class="card"><div class="label">CPU Usage</div><div class="value">{{CPU}}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value">{{MEM_USED}}MB / {{MEM_TOTAL}}MB ({{MEM_PCT}}%)</div></div>
  <div class="card"><div class="label">Effective Mean</div><div class="value">{{EFF_MEAN}} req/s</div></div>
  <div class="card"><div class="label">Effective StdDev</div><div class="value">{{EFF_STDDEV}}</div></div>
</div>
<h2>Banned IPs</h2>
<div class="card">{{BANNED_TABLE}}</div>
<h2>Top 10 Source IPs</h2>
<div class="card">{{TOP_IPS_TABLE}}</div>
<h2>Baseline Info</h2>
<div class="card">
  <p>Recalculations: {{RECALC_COUNT}} | Samples in window: {{SAMPLES}}</p>
  {{HOURLY_SLOTS}}
</div>
<div class="footer">Last refresh: {{TIMESTAMP}} | Auto-refreshes every 3 seconds</div>
</body>
</html>`