package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// LogEntry represents a parsed Nginx JSON access log line.
type LogEntry struct {
	SourceIP     string
	Timestamp    string
	Method       string
	Path         string
	Status       int
	ResponseSize int
}

// rawLogEntry maps the JSON fields from the Nginx log.
type rawLogEntry struct {
	SourceIP         string `json:"source_ip"`
	RemoteAddr       string `json:"remote_addr"`
	XForwardedFor    string `json:"http_x_forwarded_for"`
	Timestamp        string `json:"timestamp"`
	TimeLocal        string `json:"time_local"`
	Method           string `json:"method"`
	RequestMethod    string `json:"request_method"`
	Path             string `json:"path"`
	URI              string `json:"uri"`
	Status           int    `json:"status"`
	ResponseSize     int    `json:"response_size"`
	BodyBytesSent    int    `json:"body_bytes_sent"`
}

// parseLogLine parses a single JSON log line into a LogEntry.
func parseLogLine(line string) *LogEntry {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	var raw rawLogEntry
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}

	// Determine source IP
	sourceIP := raw.SourceIP
	if sourceIP == "" {
		sourceIP = raw.RemoteAddr
	}
	// Use X-Forwarded-For if available (real client IP)
	if raw.XForwardedFor != "" && raw.XForwardedFor != "-" {
		parts := strings.SplitN(raw.XForwardedFor, ",", 2)
		sourceIP = strings.TrimSpace(parts[0])
	}

	// Determine other fields with fallbacks
	ts := raw.Timestamp
	if ts == "" {
		ts = raw.TimeLocal
	}
	method := raw.Method
	if method == "" {
		method = raw.RequestMethod
	}
	path := raw.Path
	if path == "" {
		path = raw.URI
	}
	respSize := raw.ResponseSize
	if respSize == 0 {
		respSize = raw.BodyBytesSent
	}

	return &LogEntry{
		SourceIP:     sourceIP,
		Timestamp:    ts,
		Method:       method,
		Path:         path,
		Status:       raw.Status,
		ResponseSize: respSize,
	}
}

// TailLog continuously tails the Nginx access log and sends parsed
// entries to the output channel. Similar to 'tail -f'.
func TailLog(filepath string, out chan<- *LogEntry, stop <-chan struct{}) {
	log.Printf("[monitor] Waiting for log file: %s", filepath)

	// Wait for the file to exist
	for {
		select {
		case <-stop:
			return
		default:
		}
		if _, err := os.Stat(filepath); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	log.Printf("[monitor] Log file found, starting tail: %s", filepath)

	f, err := os.Open(filepath)
	if err != nil {
		log.Printf("[monitor] Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	// Seek to end — only process new entries
	f.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(f)

	for {
		select {
		case <-stop:
			log.Println("[monitor] Stopping log tail")
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			// No new data yet, wait briefly
			time.Sleep(100 * time.Millisecond)
			continue
		}

		entry := parseLogLine(line)
		if entry != nil {
			select {
			case out <- entry:
			default:
				// Channel full, drop entry to prevent blocking
			}
		}
	}
}