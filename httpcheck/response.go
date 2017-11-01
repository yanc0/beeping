package httpcheck

import (
	"fmt"
	"net"
	"net/url"
	"time"
)

// Check defines the check to do
type Check struct {
	URL      string        `json:"url" binding:"required"`
	Pattern  string        `json:"pattern"`
	Header   string        `json:"header"`
	Insecure bool          `json:"insecure"`
	Timeout  time.Duration `json:"timeout"`
	Auth     string        `json:"auth"`
}

type Timeline struct {
	NameLookup    int64 `json:"name_lookup"`
	Connect       int64 `json:"connect"`
	Pretransfer   int64 `json:"pretransfer"`
	StartTransfer int64 `json:"starttransfer"`
}

type Geo struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	IP      string `json:"ip"`
}

// Response defines the response to bring back
type Response struct {
	HTTPStatus      string `json:"http_status"`
	HTTPStatusCode  int    `json:"http_status_code"`
	HTTPBodyPattern bool   `json:"http_body_pattern"`
	HTTPHeader      bool   `json:"http_header"`
	HTTPRequestTime int64  `json:"http_request_time"`

	InstanceName string `json:"instance_name"`

	DNSLookup        int64 `json:"dns_lookup"`
	TCPConnection    int64 `json:"tcp_connection"`
	TLSHandshake     int64 `json:"tls_handshake,omitempty"`
	ServerProcessing int64 `json:"server_processing"`
	ContentTransfer  int64 `json:"content_transfer"`

	Timeline *Timeline `json:"timeline"`
	Geo      *Geo      `json:"geo,omitempty"`
	SSL      *CheckSSL `json:"ssl,omitempty"`
}

// Performs some validation checks on the target.
// Returns nil if valid, returns an error otherwise.
func (check *Check) ValidateTarget() error {
	targetURL, err := url.Parse(check.URL)
	if err != nil {
		return err
	}
	ip := net.ParseIP(targetURL.Hostname())
	if ip == nil {
		// Hostname provided is not an IP. Without whitelisting, it is not possible to tell
		// whether it is an internal hostname.
		return nil // For now, hostnames are not needed for this check.
	}

	// Check for local network IPs
	switch {
	// Loopback address
	case ip.IsLoopback():
		return fmt.Errorf("Disallowed target")
	// Link-local unicast
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("Disallowed target")
	// Link-local multicast
	case ip.IsLinkLocalMulticast():
		return fmt.Errorf("Disallowed target")
	// Private network (10.0.0.0/8)
	case len(ip) == 4 && ip[0] == 10:
		return fmt.Errorf("Disallowed target")
	// Private network (Carrier-grade NAT; 100.64.0.0/10)
	case len(ip) == 4 && ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127:
		return fmt.Errorf("Disallowed target")
	// Private network (172.16.0.0/12)
	case len(ip) == 4 && ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		return fmt.Errorf("Disallowed target")
	// Private network (192.168.0.0/16)
	case len(ip) == 4 && ip[0] == 192 && ip[1] == 16:
		return fmt.Errorf("Disallowed target")
	// Private network (fc00::/7)
	case len(ip) == 16 && (ip[0] == 0xfc || ip[0] == 0xfd):
		return fmt.Errorf("Disallowed target")
	}

	return nil
}
