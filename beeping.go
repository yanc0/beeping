package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/tcnksm/go-httpstat"
	"github.com/yanc0/beeping/sslcheck"
)

var VERSION = "0.5.0"
var MESSAGE = "BeePing instance - HTTP Ping as a Service (github.com/yanc0/beeping)"
var USERAGENT = "Beeping " + VERSION + " - https://github.com/yanc0/beeping"

var geodatfile *string
var instance *string
var listen *string
var port *string
var tlsmode *bool
var validatetarget *bool

type ErrorMessage struct {
	Message string `json:"message"`
}

type Beeping struct {
	Version string `json:"version"`
	Message string `json:"message"`
}

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

	Timeline *Timeline          `json:"timeline"`
	Geo      *Geo               `json:"geo,omitempty"`
	SSL      *sslcheck.CheckSSL `json:"ssl,omitempty"`
}

func NewErrorMessage(message string) *ErrorMessage {
	var response = ErrorMessage{}
	response.Message = message
	return &response
}

func InvalidJSONResponse() *ErrorMessage {
	return NewErrorMessage("Invalid JSON sent")
}

func NewResponse() *Response {
	var response = Response{}
	response.Timeline = &Timeline{}
	return &response
}

func NewCheck() *Check {
	return &Check{Timeout: 10}
}

// Performs some validation checks on the target.
// Returns nil if valid, returns an error otherwise.
func (check *Check) validateTarget() error {
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

func main() {
	geodatfile = flag.String("geodatfile", "/opt/GeoIP/GeoLite2-City.mmdb", "geoIP database path")
	instance = flag.String("instance", "", "beeping instance name (default hostname)")
	listen = flag.String("listen", "127.0.0.1", "The host to bind the server to")
	port = flag.String("port", "8080", "The port to bind the server to")
	tlsmode = flag.Bool("tlsmode", false, "Activate SSL/TLS versions and Cipher support checks (slow)")
	validatetarget = flag.Bool("validatetarget", true, "Perform some security checks on the target provided")
	flag.Parse()

	http.HandleFunc("/check", handlerCheck)
	http.HandleFunc("/", handlerDefault)

	log.Println("[INFO] Listening on", *listen, *port)
	if err := http.ListenAndServe(*listen+":"+*port, nil); err != nil {
		log.Fatalf("could not listen on %s:%s: %v", *listen, *port, err)
	}
}

func handlerDefault(w http.ResponseWriter, r *http.Request) {
	var beeping Beeping
	beeping.Version = VERSION
	beeping.Message = MESSAGE
	log.Println("[INFO] Beeping version", beeping.Version)
	jsonRes, _ := json.Marshal(beeping)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonRes)
}

func handlerCheck(w http.ResponseWriter, r *http.Request) {
	var check = NewCheck()

	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&check)
	if err != nil {
		log.Println("[WARN] Invalid JSON sent")
		jsonRes, _ := json.Marshal(InvalidJSONResponse())
		w.Write(jsonRes)
		return
	}

	if !*validatetarget {
		response, err := CheckHTTP(check)
		if err != nil {
			log.Println("[WARN] Check failed:", err.Error())
			jsonRes, _ := json.Marshal(NewErrorMessage(err.Error()))
			w.Write(jsonRes)
			return
		}
		log.Println("[INFO] Successful check:", check.URL, "-", response.HTTPRequestTime, "ms")
		jsonRes, _ := json.Marshal(response)
		w.Write(jsonRes)
		return
	}

	if err := check.validateTarget(); err != nil {
		log.Println("[WARN] Invalid target:", err.Error())
		jsonRes, _ := json.Marshal(NewErrorMessage(err.Error()))
		w.Write(jsonRes)
		return
	}

	response, err := CheckHTTP(check)
	if err != nil {
		log.Println("[WARN] Check failed:", err.Error())
		jsonRes, _ := json.Marshal(NewErrorMessage(err.Error()))
		w.Write(jsonRes)
		return
	}

	log.Println("[INFO] Successful check:", check.URL, "-", response.HTTPRequestTime, "ms")
	jsonRes, _ := json.Marshal(response)
	w.Write(jsonRes)
}

// CheckHTTP do HTTP check and return a beeping response
func CheckHTTP(check *Check) (*Response, error) {
	var response = NewResponse()
	var conn net.Conn

	req, err := http.NewRequest("GET", check.URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", USERAGENT)

	if len(check.Auth) > 0 {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(check.Auth)))
	}

	// Create go-httpstat powered context and pass it to http.Request
	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)

	// Add IP:PORT tracing to the context
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			conn = i.Conn
		},
	})

	req = req.WithContext(ctx)

	// DefaultClient is not suitable cause it caches
	// tcp connection https://golang.org/pkg/net/http/#Client
	// Allow us to close Idle connections and reset network
	// metrics each time
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: check.Insecure,
		},
	}

	timeout := time.Duration(check.Timeout * time.Second)

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	res.Body.Close()
	timeEndBody := time.Now()
	result.End(timeEndBody)
	var total = result.Total(timeEndBody)

	tr.CloseIdleConnections()

	pattern := strings.Contains(string(body), check.Pattern)

	header := true
	if check.Header != "" {
		key, value := splitCheckHeader(check.Header)
		if key != "" && value != "" && res.Header.Get(key) != value {
			header = false
		}
	}

	response.HTTPStatus = res.Status
	response.HTTPStatusCode = res.StatusCode
	response.HTTPBodyPattern = pattern
	response.HTTPHeader = header
	response.HTTPRequestTime = milliseconds(total)
	response.Timeline.NameLookup = milliseconds(result.NameLookup)
	response.Timeline.Connect = milliseconds(result.Connect)
	response.Timeline.Pretransfer = milliseconds(result.Pretransfer)
	response.Timeline.StartTransfer = milliseconds(result.StartTransfer)
	response.DNSLookup = milliseconds(result.DNSLookup)
	response.TCPConnection = milliseconds(result.TCPConnection)
	response.TLSHandshake = milliseconds(result.TLSHandshake)
	response.ServerProcessing = milliseconds(result.ServerProcessing)
	response.ContentTransfer = milliseconds(result.ContentTransfer(timeEndBody))

	if res.TLS != nil {
		cTLS := &sslcheck.CheckSSL{}
		if *tlsmode {
			cTLS.CheckCiphers(conn)
			cTLS.CheckVersions(conn)
		}
		cTLS.CertExpiryDate = res.TLS.PeerCertificates[0].NotAfter
		cTLS.CertExpiryDaysLeft = int64(cTLS.CertExpiryDate.Sub(time.Now()).Hours() / 24)
		cTLS.CertSignature = res.TLS.PeerCertificates[0].SignatureAlgorithm.String()
		response.SSL = cTLS
	}

	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Println("[WARN] Cannot parse IP address", err.Error())
	}

	_ = geoIPCountry(*geodatfile, ip, response)

	err = instanceName(*instance, response)
	if err != nil {
		log.Println("[WARN] Cannot set instance name", err.Error())
	}

	return response, nil
}

func milliseconds(d time.Duration) int64 {
	return d.Nanoseconds() / 1000 / 1000
}

func geoIPCountry(geodatabase string, ip string, response *Response) error {
	db, err := geoip2.Open(geodatabase)
	if err != nil {
		return err
	}
	defer db.Close()
	// If you are using strings that may be invalid, check that ip is not nil
	ipParse := net.ParseIP(ip)
	record, err := db.City(ipParse)
	if err != nil {
		return err
	}
	response.Geo = &Geo{}
	response.Geo.Country = record.Country.IsoCode
	response.Geo.IP = ip
	if record.Country.Names != nil {
		response.Geo.City = record.City.Names["en-EN"]
	}
	return nil
}

func instanceName(name string, response *Response) error {
	var err error
	response.InstanceName = name
	if name == "" {
		response.InstanceName, err = os.Hostname()
		if err != nil {
			return err
		}
	}

	return nil
}

func splitCheckHeader(header string) (string, string) {
	h := strings.SplitN(header, ":", 2)
	if len(h) == 2 {
		return strings.TrimSpace(h[0]), strings.TrimSpace(h[1])
	}
	return "", ""
}
