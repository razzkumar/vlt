ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app

RUN --mount=type=cache,target=/go/pkg/mod/ \
  --mount=type=bind,source=go.mod,target=go.mod \
  --mount=type=bind,source=go.sum,target=go.sum \
  go mod download -x

COPY . .

RUN mkdir -p /out/build

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod/ CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/build/vlt ./cmd/cli

FROM scratch AS prod

WORKDIR /app

LABEL org.opencontainers.image.title="Vlt"

COPY --from=builder /out/build/vlt /usr/local/bin/vlt

CMD ["vlt"]
