# Pingmeback v0.2.0
[![Build Status](https://travis-ci.org/yanc0/pingmeback.svg?branch=master)](https://travis-ci.org/yanc0/pingmeback)


 :telephone\_receiver: HTTP Service for today web monitoring. Pingmeback is a
distant http check as a Service. It is really useful for example when a
webserver wants to know if its application is reachable from the internet in
a reasonable time. This service can be used alongside Sensu monitoring.

Another use case is to ask for checks from differents countries
and measure responses time.

Big hugs to :

* Dave Cheney for his inspirational work on [httpstat](https://github.com/davecheney/httpstat)
* Taichi Nakashima for his work on httpstat lib [go-httpstat](https://github.com/tcnksm/go-httpstat)

## Install

Download latest version on [releases page](https://github.com/yanc0/pingmeback/releases)

- `chmod +x pingmeback`
- `sudo mv pingmeback /usr/bin`
- `pingmeback`

Pingmeback listens on 8080

## Build
`go get -u github.com/yanc0/pingmeback`

## API Usage

```
$ curl -XPOST http://pingback.me.com/check -d '{"url": "https://www.mysite.com/cats", "pattern": "grumpy cat", "insecure": false, "timeout": 20}
{
  "http_status": "200 OK",
  "http_status_code": 200,
  "http_body_pattern": true,
  "http_request_time": 942,
  "dns_lookup": 2,
  "tcp_connection": 1,
  "tls_handshake": 80,
  "server_processing": 858,
  "content_transfer": 0,
  "timeline": {
    "name_lookup": 2,
    "connect": 3,
    "pretransfer": 84,
    "starttransfer": 942
  },
  "ssl": true,
  "ssl_expiry_date": "2018-11-22T23:59:59Z",
  "ssl_days_left": 616
}
```

* If pattern is not filled `http_body_pattern` is always `true`
* `tls_handshake`, `ssl_expiry_data` and `ssl_days_left` are not shown when `http://` only

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
