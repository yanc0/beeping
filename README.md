# BeePing v0.5.0
[![Build Status](https://travis-ci.org/yanc0/beeping.svg?branch=master)](https://travis-ci.org/yanc0/beeping)

_previously named pingmeback_

  > It forages the servers and brings the metrics back to the hive

![beeping](http://oi68.tinypic.com/2yngw9h.jpg)  

BeePing is a distant http check as a Service. Call the very simple API, BeePing
will measure website for you.

:us::green_heart: 200 OK - **119 ms**  
:book: DNS - **9 ms**  
:arrows_counterclockwise: TCP - **6 ms**  
:lock: TLS - **52 ms**  
:desktop_computer: Server Processing - **43 ms**  
:arrow_down_small: Transfer - **6 ms**  

Features:

* Very simple JSON API
* Lot of metrics
* Timeline of HTTP request
* SSL Expiration check
* Server SSL/TLS version and Ciphers
* Pattern check (search for text in response)
* GeoIP resolution
* Single binary

Big hugs to :

* Dave Cheney for his inspirational work on [httpstat](https://github.com/davecheney/httpstat)
* Taichi Nakashima for his work on httpstat lib [go-httpstat](https://github.com/tcnksm/go-httpstat)

## Install

Download latest version on [releases page](https://github.com/yanc0/beeping/releases)

- `chmod +x beeping`
- `sudo mv beeping /usr/bin`
- `beeping`

```
$ ./beeping -h
Usage of ./beeping:
  -geodatfile string
        geoIP database path (default "/opt/GeoIP/GeoLite2-City.mmdb")
  -instance string
        beeping instance name (default hostname)
  -listen string
        The host to bind the server to (default "127.0.0.1")
  -port string
        The port to bind the server to (default "8080")
  -tlsmode
        Activate SSL/TLS versions and Cipher support checks (slow)
  -validatetarget
          Perform some security checks on the target provided (default true)
```

**Notes**

* If no GeoIP database is found, BeePing omit geo response silently
* TLSMode returns more infos on SSL object. It tries the more ciphers and TLS version
  Golang can test but the checks can be way slower.

### Optional

You can plug MaxMind GeoIP file to know on which country the pings goes.

See: http://dev.maxmind.com/geoip/geoip2/geolite2/

## Build

Beeping is known to only compile with Golang 1.8.x + (see [#14](../../issues/14) )

```shell
go get -u github.com/golang/dep
go get -u github.com/yanc0/beeping
cd $GOPATH/src/github.com/yanc0/beeping
dep ensure
go build
```

## API Usage

```
$ curl -XPOST http://localhost:8080/check -d '{"url": "https://google.fr", "pattern": "find me", "header": "Server:GitHub.com", "insecure": false, "timeout": 20}
{
  "http_status": "200 OK",
  "http_status_code": 200,
  "http_body_pattern": true,
  "http_header": true,
  "http_request_time": 716,
  "instance_name": "X250",
  "dns_lookup": 14,
  "tcp_connection": 101,
  "tls_handshake": 228,
  "server_processing": 168,
  "content_transfer": 203,
  "timeline": {
    "name_lookup": 14,
    "connect": 115,
    "pretransfer": 344,
    "starttransfer": 512
  },
  "geo": {
    "country": "US",
    "ip": "192.30.253.112"
  },
  "ssl": {
    "ciphers": [
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_RC4_128_SHA",
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
    ],
    "protocol_versions": [
      "TLS12",
      "TLS10",
      "TLS11"
    ],
    "cert_expiry_date": "2018-05-17T12:00:00Z",
    "cert_expiry_days_left": 374,
    "cert_signature": "SHA256-RSA"
  }
}
```

* If pattern is not filled `http_body_pattern` is always `true`
* If header is not filled `http_header` is always `true`
* `ssl` is omitted when `http://`. The same for the `tls_handshake` field
* `geo` is omitted if geoip is not set

## Beeping Clients

* beeping-client (python) : you can use the [beeping-client](https://github.com/QuentinDeSoete/beeping-client) made by [Quentin De Soete](https://github.com/QuentinDeSoete), in Python.

## Error Handling

beeping returns HTTP 500 when check fail. The body contains the reason of the failure.

```
{
  "message": "Get https://mysite.com/health: net/http: request canceled (Client Timeout exceeded while awaiting headers)"
}
```

## HTTP Basic Auth

Just add the 'auth' option in your JSON.

```
$ curl -XPOST http://localhost:8080/check -d '{"url":"http://127.0.0.1:3000","auth":"john:secret"}'
```

## Changelog

### 0.6.0 - UNRELEASED

  * Validate target - CWE-918 [#16](../../pulls/16) [Aaron Hnatiw](https://github.com/insp3ctre)
  * Include remote address in request header [#19](../../pulls/19) [Aaron Hnatiw](https://github.com/insp3ctre)
  * Basic HTTP auth [#23](../../pulls/23) [Brice Colucci](https://github.com/bcolucci)
  * Go native HTTP server instead of Gin [#24](../../pulls/24) [Brice Colucci](https://github.com/bcolucci)

### 0.5.0 - 2017-05-07

  * Add TLS Mode, now show server supported ciphers and SSL/TLS versions
  * Add listen / Port options (**breaking change**)
  * Modify JSON response structure (**breaking change**)
  * Add proper logging
  * Set proper User-Agent
  * Add header check

### 0.4.0 - 2017-04-24

  * Pingmeback is now BeePing
  * Add BeePing logo
  * Adapt documentation
  * Change Travis build info

### 0.3.0 - 2017-04-21

  * pingmeback now returns geoip informations
  * Add Instance name in results
  * Add vendoring system


## To Do

- [x] Add HTTP Auth
- [ ] Add tests
- [ ] More metrics
- [ ] Packaging

## Contributing

Feel free to make a pull request.

## Contributors

 * Aaron Hnatiw
 * Aimof
 * Brice Colucci
 * Yann Coleu

## Licence

```
The MIT License (MIT)

Copyright (c) 2016 Yann Coleu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
