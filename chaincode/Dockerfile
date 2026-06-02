# Chaincode-as-a-Service 镜像（避免 peer 容器内 docker build 在 WSL2 上 broken pipe）
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS builder
RUN apk add --no-cache git
WORKDIR /chaincode
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 GOOS=linux GOWORK=off
RUN go build -o /chaincode/bin/chaincode .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /chaincode
COPY --from=builder /chaincode/bin/chaincode .
ARG CC_SERVER_PORT=9999
EXPOSE ${CC_SERVER_PORT}
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:${CC_SERVER_PORT}
CMD ["./chaincode"]
