FROM golang:1.23.0

WORKDIR /usr/src/app

COPY . .

RUN go mod tidy
