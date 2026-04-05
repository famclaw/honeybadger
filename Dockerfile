FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -trimpath -buildvcs=false \
    -o /honeybadger ./cmd/honeybadger

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /honeybadger /honeybadger

ENTRYPOINT ["/honeybadger"]
