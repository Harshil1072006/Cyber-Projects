package idle

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/net"
)

type Detector struct {
	ThresholdBytesPerInterval uint64
	SampleInterval            time.Duration
	MaxWaitMultiplier         int
	interfaceName             string
}

func NewDetector(ifaceName string) *Detector {
	return &Detector{
		ThresholdBytesPerInterval: 512,
		SampleInterval:            2 * time.Second,
		MaxWaitMultiplier:         2,
		interfaceName:             ifaceName,
	}
}

// WaitUntilIdle blocks until the network is idle OR maxWait is exceeded.
// Returns true if idle, false if forced (timed out).
func (d *Detector) WaitUntilIdle(ctx context.Context, maxWait time.Duration) bool {
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
			if d.isIdle() {
				return true
			}
		}
	}
	return false // force-rotate (hard timeout)
}

func (d *Detector) isIdle() bool {
	s1, err := net.IOCounters(true)
	if err != nil {
		return true // assume idle on error
	}

	time.Sleep(d.SampleInterval)

	s2, err := net.IOCounters(true)
	if err != nil {
		return true
	}

	for i, iface := range s2 {
		if iface.Name == d.interfaceName || d.interfaceName == "" { // If empty, check all? Or just VPN interface
			bytesDelta := (iface.BytesSent + iface.BytesRecv) - (s1[i].BytesSent + s1[i].BytesRecv)
			return bytesDelta < d.ThresholdBytesPerInterval
		}
	}
	
	// If interface not found, assume idle
	return true
}
