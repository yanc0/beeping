# Pingmeback v0.3.0
[![Build Status](https://travis-ci.org/yanc0/pingmeback.svg?branch=master)](https://travis-ci.org/yanc0/pingmeback)


 :telephone\_receiver: HTTP Service for today web monitoring. Pingmeback is a
distant http check as a Service. Deploy instances in seconds and measure your
websites from anywhere in the world.

Big hugs to :

* Dave Cheney for his inspirational work on [httpstat](https://github.com/davecheney/httpstat)
* Taichi Nakashima for his work on httpstat lib [go-httpstat](https://github.com/tcnksm/go-httpstat)

## Install

Download latest version on [releases page](https://github.com/yanc0/pingmeback/releases)

- `chmod +x pingmeback`
- `sudo mv pingmeback /usr/bin`
- `pingmeback`

```
$ ./pingmeback -h
Usage of ./pingmeback:
  -geodatfile string
    	geoIP database path (default "/opt/GeoIP/GeoLite2-City.mmdb")
  -instance string
    	pingmeback instance name (default hostname)
```

Pingmeback listens on 8080

### Optional

You can plug MaxMind GeoIP file to know on which country the pings goes.

See: http://dev.maxmind.com/geoip/geoip2/geolite2/

## Build
```shell
go get -u github.com/golang/dep
go get -u github.com/yanc0/pingmeback
cd $GOPATH/src/github.com/yanc0/pingmeback
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
* `tls_handshake`, `ssl_expiry_data` and `ssl_days_left` are not shown when `http://` only
* `geo` is omitted if geoip is not set

## Error Handling

Pingmeback returns HTTP 500 when check fail. The body contains the reason of the failure.

```
{
  "message": "Get https://mysite.com/health: net/http: request canceled (Client Timeout exceeded while awaiting headers)"
}
```

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
