package cache

type VPNServer struct {
	HostName         string `json:"host_name"`
	IP               string `json:"ip"`
	Score            int64  `json:"score"`
	Ping             int    `json:"ping"`
	Speed            int64  `json:"speed"` // bps
	CountryLong      string `json:"country_long"`
	CountryShort     string `json:"country_short"` // e.g. "JP", "US"
	NumVPNSessions   int    `json:"num_vpn_sessions"`
	OpenVPNConfigB64 string `json:"openvpn_config_b64"`
}
