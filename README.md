# Pingmeback
HTTP Service for today web monitoring

## Build
`go get -u github.com/yanc0/pingmeback`

## API Usage

`curl -XPOST pingmeback.local -d '{"url": "https://www.google.com"}`

```
{"http_status":"200 OK","http_status_code":200,"http_body":"<redacted>","http_request_time":471,"ssl":true,"ssl_expiry_date":"2016-05-31T00:00:00Z"}

```

## Contributing

Feel free to make a pull request
