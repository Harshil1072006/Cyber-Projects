package cache

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vpnGateURL     = "http://www.vpngate.net/api/iphone/"
	cacheFile      = "vpngate_cache.json"
	cacheExpiry    = 1 * time.Hour
)

type CacheManager struct {
	servers []VPNServer
	mu      sync.RWMutex
}

type CacheData struct {
	UpdatedAt time.Time   `json:"updated_at"`
	Servers   []VPNServer `json:"servers"`
}

func NewCacheManager() *CacheManager {
	return &CacheManager{
		servers: make([]VPNServer, 0),
	}
}

// LoadOrFetch checks if the cache is valid. If not, it fetches from the API.
func (c *CacheManager) LoadOrFetch() error {
	if c.isCacheFresh() {
		return c.loadFromDisk()
	}
	
	err := c.fetchAndSave()
	if err != nil {
		// If fetch fails, try to load stale cache as fallback
		if loadErr := c.loadFromDisk(); loadErr == nil {
			return nil // returning nil because we successfully loaded stale cache
		}
		return err
	}
	
	return nil
}

// StartAutoRefresh starts a background goroutine to refresh the cache every hour.
func (c *CacheManager) StartAutoRefresh() {
	go func() {
		ticker := time.NewTicker(cacheExpiry)
		defer ticker.Stop()
		for range ticker.C {
			_ = c.fetchAndSave()
		}
	}()
}

// GetServers returns a copy of the currently cached servers.
func (c *CacheManager) GetServers() []VPNServer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	serversCopy := make([]VPNServer, len(c.servers))
	copy(serversCopy, c.servers)
	return serversCopy
}

// isCacheFresh returns true if the cache file exists and is less than 1 hour old.
func (c *CacheManager) isCacheFresh() bool {
	info, err := os.Stat(cacheFile)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < cacheExpiry
}

func (c *CacheManager) loadFromDisk() error {
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return err
	}
	
	var cacheData CacheData
	if err := json.Unmarshal(data, &cacheData); err != nil {
		return err
	}
	
	c.mu.Lock()
	c.servers = cacheData.Servers
	c.mu.Unlock()
	
	return nil
}

func (c *CacheManager) fetchAndSave() error {
	resp, err := http.Get(vpnGateURL)
	if err != nil {
		return fmt.Errorf("failed to fetch VPN Gate API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	servers, err := parseCSV(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse CSV: %w", err)
	}
	
	// Update in memory
	c.mu.Lock()
	c.servers = servers
	c.mu.Unlock()
	
	// Save to disk
	return c.saveToDisk(servers)
}

func (c *CacheManager) saveToDisk(servers []VPNServer) error {
	cacheData := CacheData{
		UpdatedAt: time.Now(),
		Servers:   servers,
	}
	
	data, err := json.MarshalIndent(cacheData, "", "  ")
	if err != nil {
		return err
	}
	
	// Write atomically using a tmp file
	tmpFile := cacheFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	
	return os.Rename(tmpFile, cacheFile)
}

func parseCSV(r io.Reader) ([]VPNServer, error) {
	// The VPN Gate CSV starts with a note line starting with *
	// Then a header line starting with #
	// Then the data.
	
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // Variable number of fields
	reader.LazyQuotes = true
	
	var servers []VPNServer
	
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed lines
		}
		
		if len(record) == 0 || strings.HasPrefix(record[0], "*") || strings.HasPrefix(record[0], "#") {
			continue // Skip comments and headers
		}
		
		// Map fields based on VPN Gate CSV structure
		// 0:HostName, 1:IP, 2:Score, 3:Ping, 4:Speed, 5:CountryLong, 6:CountryShort, 7:NumVpnSessions, 8:Uptime, 9:Users, 10:Message, 11:OpenVPN_ConfigData_Base64
		if len(record) < 15 { // Usually 15 columns
			continue
		}
		
		openVPNConfig := record[14]
		if openVPNConfig == "" {
			continue // Skip servers without OpenVPN config
		}
		
		score, _ := strconv.ParseInt(record[2], 10, 64)
		ping, _ := strconv.Atoi(record[3])
		speed, _ := strconv.ParseInt(record[4], 10, 64)
		sessions, _ := strconv.Atoi(record[7])
		
		servers = append(servers, VPNServer{
			HostName:         record[0],
			IP:               record[1],
			Score:            score,
			Ping:             ping,
			Speed:            speed,
			CountryLong:      record[5],
			CountryShort:     record[6],
			NumVPNSessions:   sessions,
			OpenVPNConfigB64: openVPNConfig,
		})
	}
	
	return servers, nil
}
