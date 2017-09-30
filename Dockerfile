FROM golang:1.9.0-alpine3.6

RUN apk --no-cache add git make

WORKDIR /go/src/slackhq/go-audit
COPY . .

RUN go get -u github.com/kardianos/govendor
RUN make

FROM alpine:3.6
COPY --from=0 /go/src/slackhq/go-audit/go-audit /usr/local/bin/
CMD ["/usr/local/bin/go-audit"]
