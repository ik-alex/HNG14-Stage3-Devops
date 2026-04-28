package main

import (
	"fmt"
	"log"
	"time"
)

// Unbanner periodically checks for expired bans and releases them.
type Unbanner struct {
	blocker       *IPBlocker
	notifier      *SlackNotifier
	auditCallback func(action, ip, condition string, rate, baseline float64, duration string)
	checkInterval time.Duration
}

// NewUnbanner creates a new unbanner.
func NewUnbanner(blocker *IPBlocker, notifier *SlackNotifier) *Unbanner {
	return &Unbanner{
		blocker:       blocker,
		notifier:      notifier,
		checkInterval: 10 * time.Second,
	}
}

// Run starts the unbanner loop. Blocks until stop is closed.
func (u *Unbanner) Run(stop <-chan struct{}) {
	log.Println("[unbanner] Started")
	ticker := time.NewTicker(u.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("[unbanner] Stopped")
			return
		case <-ticker.C:
			expired := u.blocker.GetExpiredBans()
			for _, ip := range expired {
				banInfo := u.blocker.UnbanIP(ip)
				if banInfo == nil {
					continue
				}

				log.Printf("[unbanner] Auto-unbanned %s after %d minutes (ban #%d)",
					ip, banInfo.DurationMinutes, banInfo.BanCount)

				// Slack notification
				u.notifier.SendUnbanAlert(ip, banInfo)

				// Audit log
				if u.auditCallback != nil {
					u.auditCallback(
						"UNBAN", ip, banInfo.Condition,
						banInfo.Rate, banInfo.Baseline,
						fmt.Sprintf("%dm", banInfo.DurationMinutes),
					)
				}
			}
		}
	}
}