package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
	"sync"
	"time"
)

// BanInfo holds information about a banned IP.
type BanInfo struct {
	IP              string  `json:"ip"`
	BannedAt        float64 `json:"-"`
	DurationMinutes int     `json:"duration_minutes"`
	BanCount        int     `json:"ban_count"`
	Condition       string  `json:"condition"`
	Rate            float64 `json:"rate"`
	Baseline        float64 `json:"baseline"`
}

// BannedIPInfo is a dashboard-friendly summary of a ban.
type BannedIPInfo struct {
	IP             string  `json:"ip"`
	Duration       string  `json:"duration"`
	ElapsedMinutes float64 `json:"elapsed_minutes"`
	BanCount       int     `json:"ban_count"`
	Condition      string  `json:"condition"`
	Rate           float64 `json:"rate"`
}

// IPBlocker manages iptables DROP rules for banned IPs.
// Tracks ban history for escalating durations.
type IPBlocker struct {
	mu sync.Mutex

	banDurations []int
	whitelist    map[string]bool

	bannedIPs  map[string]*BanInfo
	banHistory map[string]int // ip -> total ban count
}

// NewIPBlocker creates a new blocker from config.
func NewIPBlocker(cfg *Config) *IPBlocker {
	wl := make(map[string]bool)
	for _, ip := range cfg.WhitelistIPs {
		wl[ip] = true
	}

	return &IPBlocker{
		banDurations: cfg.BanDurationsMinutes,
		whitelist:    wl,
		bannedIPs:    make(map[string]*BanInfo),
		banHistory:   make(map[string]int),
	}
}

// BanIP bans an IP using iptables. Returns ban info or nil if already banned/whitelisted.
func (b *IPBlocker) BanIP(ip, condition string, rate, baseline float64) *BanInfo {
	if b.whitelist[ip] {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.bannedIPs[ip]; exists {
		return nil
	}

	// Determine ban duration based on history
	banCount := b.banHistory[ip]
	durationIndex := banCount
	if durationIndex >= len(b.banDurations) {
		durationIndex = len(b.banDurations) - 1
	}
	durationMinutes := b.banDurations[durationIndex]

	// Add iptables rule
	if !addIptablesRule(ip) {
		return nil
	}

	info := &BanInfo{
		IP:              ip,
		BannedAt:        float64(time.Now().Unix()),
		DurationMinutes: durationMinutes,
		BanCount:        banCount + 1,
		Condition:       condition,
		Rate:            rate,
		Baseline:        baseline,
	}

	b.bannedIPs[ip] = info
	b.banHistory[ip] = banCount + 1

	durStr := "permanent"
	if durationMinutes > 0 {
		durStr = fmt.Sprintf("%d minutes", durationMinutes)
	}

	log.Printf("[blocker] BANNED %s | condition: %s | rate: %.2f | baseline: %.2f | duration: %s | ban #%d",
		ip, condition, rate, baseline, durStr, banCount+1)

	return info
}

// UnbanIP removes iptables rule and unbans an IP.
func (b *IPBlocker) UnbanIP(ip string) *BanInfo {
	b.mu.Lock()
	defer b.mu.Unlock()

	info, exists := b.bannedIPs[ip]
	if !exists {
		return nil
	}

	delete(b.bannedIPs, ip)
	removeIptablesRule(ip)

	log.Printf("[blocker] UNBANNED %s after ban #%d", ip, info.BanCount)
	return info
}

// GetExpiredBans returns IPs whose ban duration has expired.
func (b *IPBlocker) GetExpiredBans() []string {
	now := float64(time.Now().Unix())
	var expired []string

	b.mu.Lock()
	defer b.mu.Unlock()

	for ip, info := range b.bannedIPs {
		if info.DurationMinutes < 0 {
			continue // permanent
		}
		elapsed := (now - info.BannedAt) / 60
		if elapsed >= float64(info.DurationMinutes) {
			expired = append(expired, ip)
		}
	}

	return expired
}

// GetBannedIPs returns a dashboard-friendly list of banned IPs.
func (b *IPBlocker) GetBannedIPs() []BannedIPInfo {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := float64(time.Now().Unix())
	var result []BannedIPInfo

	for ip, info := range b.bannedIPs {
		dur := "permanent"
		if info.DurationMinutes > 0 {
			dur = fmt.Sprintf("%dm", info.DurationMinutes)
		}
		elapsed := (now - info.BannedAt) / 60

		result = append(result, BannedIPInfo{
			IP:             ip,
			Duration:       dur,
			ElapsedMinutes: math.Round(elapsed*10) / 10,
			BanCount:       info.BanCount,
			Condition:      info.Condition,
			Rate:           info.Rate,
		})
	}

	return result
}

// addIptablesRule adds a DROP rule for an IP.
func addIptablesRule(ip string) bool {
	// Check if rule exists
	check := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if check.Run() == nil {
		return true // already exists
	}

	// Add rule
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[blocker] Failed to add iptables rule for %s: %s %v", ip, string(out), err)
		return false
	}

	log.Printf("[blocker] iptables DROP rule added for %s", ip)
	return true
}

// removeIptablesRule removes a DROP rule for an IP.
func removeIptablesRule(ip string) bool {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[blocker] Failed to remove iptables rule for %s: %s %v", ip, string(out), err)
		return false
	}

	log.Printf("[blocker] iptables DROP rule removed for %s", ip)
	return true
}