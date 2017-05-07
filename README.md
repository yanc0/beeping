# BeePing v0.4.0
[![Build Status](https://travis-ci.org/yanc0/beeping.svg?branch=master)](https://travis-ci.org/yanc0/beeping)

_previously named pingmeback_

  > It forage the servers and brings the metrics back to the hive
  
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
```

beeping listens on 8080. You can choose the port by setting PORT env var

`PORT=3000 /usr/bin/beeping`

If no GeoIP database is found, BeePing omit geo response silently

### Optional

You can plug MaxMind GeoIP file to know on which country the pings goes.

See: http://dev.maxmind.com/geoip/geoip2/geolite2/

## Build
```shell
go get -u github.com/golang/dep
go get -u github.com/yanc0/beeping
cd $GOPATH/src/github.com/yanc0/beeping
dep ensure
go build
```

## API Usage

```
$ curl -XPOST http://localhost:8080/check -d '{"url": "https://google.fr", "pattern": "find me", "insecure": false, "timeout": 20}
{
  "http_status": "200 OK",
  "http_status_code": 200,
  "http_body_pattern": true,
  "http_request_time": 119,
  "instance_name": "X250",
  "dns_lookup": 9,
  "tcp_connection": 6,
  "tls_handshake": 52,
  "server_processing": 43,
  "content_transfer": 6,
  "timeline": {
    "name_lookup": 9,
    "connect": 16,
    "pretransfer": 68,
    "starttransfer": 112
  },
  "geo": {
    "country": "US",
    "ip": "216.58.209.227"
  },
  "ssl": true,
  "ssl_expiry_date": "2017-07-05T13:28:00Z",
  "ssl_days_left": 74
}
```

* If pattern is not filled `http_body_pattern` is always `true`
* `tls_handshake`, `ssl_expiry_date` and `ssl_days_left` are not shown when `http://` only
* `geo` is omitted if geoip is not set

## Error Handling

beeping returns HTTP 500 when check fail. The body contains the reason of the failure.

```
{
  "message": "Get https://mysite.com/health: net/http: request canceled (Client Timeout exceeded while awaiting headers)"
}
```

## Changelog

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

- [ ] Add HTTP Auth
- [ ] Add tests
- [ ] More metrics
- [ ] Packaging

## Contributing

Feel free to make a pull request.

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
