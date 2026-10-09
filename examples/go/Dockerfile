FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go/go.mod go/go.sum ./go/
COPY examples/go/go.mod examples/go/go.sum ./examples/go/
RUN cd examples/go && go mod download
COPY go ./go
COPY examples/go ./examples/go
RUN cd examples/go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /gateway /gateway
EXPOSE 8080
ENTRYPOINT ["/gateway"]
