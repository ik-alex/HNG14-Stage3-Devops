# Anomaly Detection Engine — DDoS Detection Tool

A Go-based daemon that monitors Nginx access logs in real time, learns normal traffic patterns using rolling statistical baselines, and automatically detects and responds to anomalous traffic — whether from a single aggressive IP or a global traffic spike.

Built to run alongside a Nextcloud instance behind an Nginx reverse proxy.

## Live Links

- **Server IP:** `52.87.201.41`
- **Metrics Dashboard:** `http://ikalex.duckdns.org:5000`
- **Nextcloud:** `http://52.87.201.41`

## Language Choice: Go

Go was chosen for:

- Native concurrency with goroutines — each component (monitor, detector, unbanner, dashboard) runs in its own goroutine with zero external dependencies
- Low memory footprint and fast startup — important for a daemon running 12+ hours
- Single static binary — no runtime dependencies, trivial to containerize
- Built-in HTTP server for the dashboard
- Strong standard library for JSON parsing, file I/O, and exec

## Architecture

```
Internet Traffic
       |
       v
+--------------+
|    Nginx     |---- JSON access log ----> /var/log/nginx/hng-access.log
|  (port 80)   |                                    |
+------+-------+                                    |
       |                              +-------------v--------------+
       v                              |   Anomaly Detector Daemon  |
+--------------+                      |                            |
|  Nextcloud   |                      |  monitor.go  -> tail log   |
|  (upstream)  |                      |  detector.go -> sliding win|
+--------------+                      |  baseline.go -> rolling avg|
                                      |  blocker.go  -> iptables   |
                                      |  unbanner.go -> auto-unban |
                                      |  notifier.go -> Slack alert|
                                      |  dashboard.go -> web UI    |
                                      +----------------------------+
```

## How the Sliding Window Works

Two slice-based sliding windows track request rates over the last 60 seconds:

1. **Per-IP window:** Each IP gets its own `SlidingWindow`. Every request appends a Unix timestamp to the slice. On each read, entries older than 60 seconds are evicted from the front. Rate = `len(slice) / 60`.

2. **Global window:** Same structure, records every request regardless of IP.

**Eviction logic:** `evict(now)` iterates from index 0 while `events[i] < now - 60`, then reslices. This keeps the window tight and memory bounded.

No rate-limiting libraries are used. The sliding window is built from scratch.

## How the Baseline Works

- **Window size:** 30 minutes of per-second request counts
- **Recalculation interval:** Every 60 seconds
- **Per-hour slots:** Maintains separate hourly slots (0-23). When the current hour's slot has >= 10 samples, it's preferred over the global window — this provides time-of-day awareness
- **Floor values:** Mean floor = 1.0 req/s, StdDev floor = 0.5. Prevents zero baselines from triggering false positives
- **The baseline is never hardcoded** — it adapts to actual traffic

## How Detection Works

An IP or global rate is flagged as anomalous if **either** condition fires:

1. **Z-score > 3.0:** Rate is more than 3 standard deviations above the baseline mean
2. **Rate > 5x baseline mean:** Simpler multiplier check for cases where stddev is low

**Error surge tightening:** If an IP's 4xx/5xx error rate exceeds 3x the baseline error rate, both thresholds are halved (z-score -> 1.5, rate multiplier -> 2.5x).

## How iptables Blocking Works

Per-IP anomaly detected:

1. `iptables -A INPUT -s <IP> -j DROP` — blocks all traffic from that IP
2. Slack alert sent within 10 seconds
3. Ban logged to audit file

**Auto-unban schedule:** 10min -> 30min -> 2h -> permanent. Each subsequent ban for the same IP escalates.

Global anomalies: Slack alert only, no blocking.

## Setup from Fresh VPS

### Prerequisites

- Linux VPS, minimum 2 vCPU / 2 GB RAM
- Docker and Docker Compose installed
- A domain pointed at your server (for the dashboard)

### Step-by-step

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in

# 2. Clone the repo
git clone https://github.com/YOUR_USERNAME/anomaly-detector.git
cd anomaly-detector

# 3. Configure Slack
cp .env.example .env
nano .env
# Paste your Slack webhook URL

# 4. Start the stack
docker compose up -d

# 5. Verify
docker compose ps
docker logs anomaly-detector
docker logs nginx-proxy

# 6. Check dashboard
curl http://localhost:5000

# 7. Check Nextcloud
curl http://YOUR_SERVER_IP
```

## Blog Post

[Link to your blog post here]

## Repository Structure

```
detector/
  main.go           # Entry point, wires components, processing loop
  config.go         # YAML config loader
  monitor.go        # Tails and parses Nginx JSON access logs
  baseline.go       # Rolling mean/stddev with per-hour slots
  detector.go       # Sliding window tracking and z-score detection
  blocker.go        # iptables DROP rule management
  unbanner.go       # Auto-releases bans on backoff schedule
  notifier.go       # Slack webhook notifications
  dashboard.go      # Live metrics web UI
  config.yaml       # All thresholds and settings
  Dockerfile        # Multi-stage Go build
  go.mod            # Go module
nginx/
  nginx.conf        # Nginx config with JSON logging
docs/
  architecture.png  # Architecture diagram
screenshots/
  (required screenshots go here)
docker-compose.yml  # Full stack orchestration
.env.example        # Environment template
README.md           # This file
```
