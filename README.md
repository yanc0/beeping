# Pingmeback
HTTP Service for today web monitoring. Pingmeback is a distant http client as
a Service. It is really useful for example when a webserver wants too know if
its application is reachable from the internet in a reasonable time. This
service can be use alongside Sensu monitoring.

## Build
`go get -u github.com/yanc0/pingmeback`

## API Usage

```
$ curl -XPOST pingmeback.local -d '{"url": "https://www.google.com"}
{
  "http_status":"200 OK",
  "http_status_code":200,
  "http_body":"[...]",
  "http_request_time":471,
  "ssl":true,
  "ssl_expiry_date":"2016-05-31T00:00:00Z"
}

```

## Contributing

Feel free to make a pull request.

## Licence

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
