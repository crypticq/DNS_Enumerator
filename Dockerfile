FROM golang:1.16-alpine

WORKDIR /eng

COPY go.mod go.sum ./

RUN go mod download

COPY subdomains-top1million-5000.txt dns.go ./ 

RUN go build dns.go

ENTRYPOINT [ "./dns" ]


