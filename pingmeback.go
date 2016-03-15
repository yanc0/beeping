package main

import (
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Check defines the check to do
type Check struct {
	URL     string `json:"url" binding:"required"`
	Pattern string `json:"pattern"`
}

// Response defines the response to bring back
type Response struct {
	HTTPStatus        string    `json:"http_status"`
	HTTPStatusCode    int       `json:"http_status_code"`
	HTTPBodyPattern   bool      `json:"http_body_pattern"`
	HTTPRequestTime   int64     `json:"http_request_time"`
	HTTPSSL           bool      `json:"ssl"`
	HTTPSSLExpiryDate time.Time `json:"ssl_expiry_date"`
}

func main() {
	router := gin.Default()
	router.POST("/check", handlercheck)
	router.Run()
}

func handlercheck(c *gin.Context) {
	var check Check
	if c.BindJSON(&check) == nil {
		response, err := CheckHTTP(&check)
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
	var response Response
	start := time.Now()
	resp, err := http.Get(check.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)
	pattern := true
	if !strings.Contains(string(body), check.Pattern) {
		pattern = false
	}
	response.HTTPStatus = resp.Status
	response.HTTPStatusCode = resp.StatusCode
	response.HTTPBodyPattern = pattern
	response.HTTPRequestTime = elapsed.Nanoseconds() / 1000 / 1000
	if resp.TLS != nil {
		response.HTTPSSL = true
		response.HTTPSSLExpiryDate = resp.TLS.PeerCertificates[0].NotAfter
	}
	return &response, nil
}
