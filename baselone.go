package main

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// SecondCount records the request count for a specific second.
type SecondCount struct {
	Timestamp float64
	Count     float64
}

// HourlySlot stores per-second counts for one clock hour.
type HourlySlot struct {
	Counts []float64
}

func (h *HourlySlot) Add(count float64) {
	// Keep max 3600 entries (1 hour of per-second counts)
	if len(h.Counts) >= 3600 {
		h.Counts = h.Counts[1:]
	}
	h.Counts = append(h.Counts, count)
}

func (h *HourlySlot) Mean() float64 {
	if len(h.Counts) == 0 {
		return 0
	}
	sum := 0.0
	for _, c := range h.Counts {
		sum += c
	}
	return sum / float64(len(h.Counts))
}

func (h *HourlySlot) StdDev() float64 {
	if len(h.Counts) < 2 {
		return 0
	}
	m := h.Mean()
	sumSq := 0.0
	for _, c := range h.Counts {
		d := c - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(h.Counts)))
}

func (h *HourlySlot) Size() int {
	return len(h.Counts)
}

// BaselineStats holds the current effective baseline for the dashboard.
type BaselineStats struct {
	EffectiveMean    float64
	EffectiveStddev  float64
	Samples          int
	RecalcCount      int
	LastRecalc       float64
	HourlySlotStats  map[int]HourlySlotStat
}

// HourlySlotStat is a summary of one hourly slot.
type HourlySlotStat struct {
	Mean float64 `json:"mean"`
	Size int     `json:"size"`
}

// BaselineCalculator computes a rolling baseline from per-second request
// counts over a 30-minute window, recalculated every 60 seconds.
// Maintains per-hour slots and prefers the current hour's baseline
// when it has enough data.
type BaselineCalculator struct {
	mu sync.RWMutex

	windowMinutes  int
	recalcInterval int
	floorMean      float64
	floorStddev    float64
	minSamples     int

	// Rolling window of per-second counts
	window []SecondCount

	// Per-hour slots (0-23)
	hourlySlots map[int]*HourlySlot

	// Error rate tracking
	errorCounts []SecondCount

	// Effective values
	effectiveMean     float64
	effectiveStddev   float64
	effectiveErrorMean float64
	lastRecalc        float64
	recalcCount       int

	// Audit callback
	AuditCallback func(action, ip, condition string, rate, baseline float64, duration string)
}

// NewBaselineCalculator creates a new baseline calculator from config.
func NewBaselineCalculator(cfg *Config) *BaselineCalculator {
	return &BaselineCalculator{
		windowMinutes:  cfg.BaselineWindowMinutes,
		recalcInterval: cfg.BaselineRecalcIntervalSecs,
		floorMean:      cfg.BaselineFloorMean,
		floorStddev:    cfg.BaselineFloorStddev,
		minSamples:     cfg.BaselineMinSamples,
		hourlySlots:    make(map[int]*HourlySlot),
		effectiveMean:  cfg.BaselineFloorMean,
		effectiveStddev: cfg.BaselineFloorStddev,
	}
}

// AddSecondCount records the request count for a given second.
func (b *BaselineCalculator) AddSecondCount(timestamp float64, totalCount, errorCount int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.window = append(b.window, SecondCount{Timestamp: timestamp, Count: float64(totalCount)})
	b.errorCounts = append(b.errorCounts, SecondCount{Timestamp: timestamp, Count: float64(errorCount)})

	// Add to hourly slot
	hour := time.Unix(int64(timestamp), 0).Hour()
	slot, ok := b.hourlySlots[hour]
	if !ok {
		slot = &HourlySlot{}
		b.hourlySlots[hour] = slot
	}
	slot.Add(float64(totalCount))

	// Evict old entries
	cutoff := timestamp - float64(b.windowMinutes*60)
	for len(b.window) > 0 && b.window[0].Timestamp < cutoff {
		b.window = b.window[1:]
	}
	for len(b.errorCounts) > 0 && b.errorCounts[0].Timestamp < cutoff {
		b.errorCounts = b.errorCounts[1:]
	}
}

// Recalculate recomputes mean and stddev from the rolling window.
func (b *BaselineCalculator) Recalculate() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	currentHour := now.Hour()

	var rawMean, rawStddev float64
	var source string

	// Prefer current hour's slot if it has enough data
	if slot, ok := b.hourlySlots[currentHour]; ok && slot.Size() >= b.minSamples {
		rawMean = slot.Mean()
		rawStddev = slot.StdDev()
		source = fmt.Sprintf("hourly_slot_%d", currentHour)
	} else if len(b.window) >= b.minSamples {
		// Use the full rolling window
		sum := 0.0
		for _, sc := range b.window {
			sum += sc.Count
		}
		rawMean = sum / float64(len(b.window))

		sumSq := 0.0
		for _, sc := range b.window {
			d := sc.Count - rawMean
			sumSq += d * d
		}
		rawStddev = math.Sqrt(sumSq / float64(len(b.window)))
		source = "rolling_window"
	} else {
		rawMean = b.floorMean
		rawStddev = b.floorStddev
		source = "floor_values"
	}

	b.effectiveMean = math.Max(rawMean, b.floorMean)
	b.effectiveStddev = math.Max(rawStddev, b.floorStddev)
	b.lastRecalc = float64(now.Unix())
	b.recalcCount++

	// Error rate baseline
	if len(b.errorCounts) > 0 {
		sum := 0.0
		for _, sc := range b.errorCounts {
			sum += sc.Count
		}
		b.effectiveErrorMean = sum / float64(len(b.errorCounts))
	}

	log.Printf("[baseline] Recalculated (#%d): mean=%.2f, stddev=%.2f, source=%s, samples=%d",
		b.recalcCount, b.effectiveMean, b.effectiveStddev, source, len(b.window))

	if b.AuditCallback != nil {
		b.AuditCallback(
			"BASELINE_RECALC", "-", source,
			rawMean, b.effectiveMean,
			fmt.Sprintf("stddev=%.2f", b.effectiveStddev),
		)
	}
}

// GetBaseline returns the current effective mean and stddev.
func (b *BaselineCalculator) GetBaseline() (float64, float64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.effectiveMean, b.effectiveStddev
}

// GetErrorBaseline returns the effective error rate mean.
func (b *BaselineCalculator) GetErrorBaseline() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.effectiveErrorMean
}

// ShouldRecalculate checks if it's time to recalculate.
func (b *BaselineCalculator) ShouldRecalculate() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return (float64(time.Now().Unix()) - b.lastRecalc) >= float64(b.recalcInterval)
}

// GetStats returns current baseline stats for the dashboard.
func (b *BaselineCalculator) GetStats() BaselineStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	hourlyStats := make(map[int]HourlySlotStat)
	for h, slot := range b.hourlySlots {
		hourlyStats[h] = HourlySlotStat{
			Mean: math.Round(slot.Mean()*100) / 100,
			Size: slot.Size(),
		}
	}

	return BaselineStats{
		EffectiveMean:   math.Round(b.effectiveMean*100) / 100,
		EffectiveStddev: math.Round(b.effectiveStddev*100) / 100,
		Samples:         len(b.window),
		RecalcCount:     b.recalcCount,
		LastRecalc:      b.lastRecalc,
		HourlySlotStats: hourlyStats,
	}
}