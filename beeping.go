package main

import (
	"crypto/tls"
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/oschwald/geoip2-golang"
	"github.com/tcnksm/go-httpstat"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"
)

var VERSION = "0.4.0"
var MESSAGE = "BeePing instance - HTTP Ping as a Service (github.com/yanc0/beeping)"
var geodatfile *string
var instance *string
var listen *string
var port *string

type PMB struct {
	Version string `json:"version"`
	Message string `json:"message"`
}

// Check defines the check to do
type Check struct {
	URL      string        `json:"url" binding:"required"`
	Pattern  string        `json:"pattern"`
	Insecure bool          `json:"insecure"`
	Timeout  time.Duration `json:"timeout"`
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
	HTTPRequestTime int64  `json:"http_request_time"`

	InstanceName string `json:"instance_name"`

	DNSLookup        int64 `json:"dns_lookup"`
	TCPConnection    int64 `json:"tcp_connection"`
	TLSHandshake     int64 `json:"tls_handshake,omitempty"`
	ServerProcessing int64 `json:"server_processing"`
	ContentTransfer  int64 `json:"content_transfer"`

	Timeline *Timeline `json:"timeline"`
	Geo      *Geo      `json:"geo,omitempty"`

	HTTPSSL           bool       `json:"ssl"`
	HTTPSSLExpiryDate *time.Time `json:"ssl_expiry_date,omitempty"`
	HTTPSSLDaysLeft   int64      `json:"ssl_days_left,omitempty"`
}

func NewResponse() *Response {
	var response = Response{}
	response.Timeline = &Timeline{}
	return &response
}

func NewCheck() *Check {
	return &Check{Timeout: 10}
}

func main() {
	geodatfile = flag.String("geodatfile", "/opt/GeoIP/GeoLite2-City.mmdb", "geoIP database path")
	instance = flag.String("instance", "", "beeping instance name (default hostname)")
	listen = flag.String("listen", "127.0.0.1", "The host to bind the server to")
	port = flag.String("port", "8080", "The port to bind the server to")
	flag.Parse()

	gin.SetMode("release")

	router := gin.Default()
	router.POST("/check", handlercheck)
	router.GET("/", handlerdefault)

	log.Println("[INFO] Listening on", *listen, *port)
	router.Run(*listen + ":" + *port)
}

func handlerdefault(c *gin.Context) {
	var pmb PMB
	pmb.Version = VERSION
	pmb.Message = MESSAGE
	c.JSON(http.StatusOK, pmb)
}

func handlercheck(c *gin.Context) {
	var check = NewCheck()
	if c.BindJSON(&check) == nil {
		response, err := CheckHTTP(check)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		} else {
			c.JSON(http.StatusOK, response)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid json sent"})
	}
}

// CheckHTTP do HTTP check and return a beeping response
func CheckHTTP(check *Check) (*Response, error) {
	var response = NewResponse()
	var conn net.Conn

	req, err := http.NewRequest("GET", check.URL, nil)
	if err != nil {
		return nil, err
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
		TLSClientConfig: &tls.Config{InsecureSkipVerify: check.Insecure},
	}

	timeout := time.Duration(check.Timeout * time.Second)

	client := &http.Client{Transport: tr, Timeout: timeout}
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

	pattern := true
	if !strings.Contains(string(body), check.Pattern) {
		pattern = false
	}

	response.HTTPStatus = res.Status
	response.HTTPStatusCode = res.StatusCode
	response.HTTPBodyPattern = pattern
	response.HTTPRequestTime = Milliseconds(total)
	response.Timeline.NameLookup = Milliseconds(result.NameLookup)
	response.Timeline.Connect = Milliseconds(result.Connect)
	response.Timeline.Pretransfer = Milliseconds(result.Pretransfer)
	response.Timeline.StartTransfer = Milliseconds(result.StartTransfer)
	response.DNSLookup = Milliseconds(result.DNSLookup)
	response.TCPConnection = Milliseconds(result.TCPConnection)
	response.TLSHandshake = Milliseconds(result.TLSHandshake)
	response.ServerProcessing = Milliseconds(result.ServerProcessing)
	response.ContentTransfer = Milliseconds(result.ContentTransfer(timeEndBody))

	if res.TLS != nil {
		response.HTTPSSL = true
		response.HTTPSSLExpiryDate = &res.TLS.PeerCertificates[0].NotAfter
		response.HTTPSSLDaysLeft = int64(response.HTTPSSLExpiryDate.Sub(time.Now()).Hours() / 24)
	}

	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Println(err.Error())
	}

	_ = geoIPCountry(*geodatfile, ip, response)

	err = instanceName(*instance, response)
	if err != nil {
		log.Println(err.Error())
	}

	return response, nil
}

func Milliseconds(d time.Duration) int64 {
	return d.Nanoseconds() / 1000 / 1000
}

func geoIPCountry(geodatabase string, ip string, response *Response) error {
	db, err := geoip2.Open(*geodatfile)
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
