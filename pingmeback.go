package main

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tcnksm/go-httpstat"
)

var VERSION = "0.2.0"
var MESSAGE = "Pingmeback instance - HTTP Ping as a Service"

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

// Response defines the response to bring back
type Response struct {
	HTTPStatus      string `json:"http_status"`
	HTTPStatusCode  int    `json:"http_status_code"`
	HTTPBodyPattern bool   `json:"http_body_pattern"`
	HTTPRequestTime int64  `json:"http_request_time"`

	DNSLookup        int64 `json:"dns_lookup"`
	TCPConnection    int64 `json:"tcp_connection"`
	TLSHandshake     int64 `json:"tls_handshake,omitempty"`
	ServerProcessing int64 `json:"server_processing"`
	ContentTransfer  int64 `json:"content_transfer"`

	Timeline *Timeline `json:"timeline"`

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
	gin.SetMode("release")
	router := gin.Default()
	router.POST("/check", handlercheck)
	router.GET("/", handlerdefault)
	router.Run()
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

// CheckHTTP do HTTP check and return a pingmeback reponse
func CheckHTTP(check *Check) (*Response, error) {
	var response = NewResponse()

	req, err := http.NewRequest("GET", check.URL, nil)
	if err != nil {
		return nil, err
	}

	// Create go-httpstat powered context and pass it to http.Request
	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)
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
	return response, nil
}

func Milliseconds(d time.Duration) int64 {
	return d.Nanoseconds() / 1000 / 1000
}
