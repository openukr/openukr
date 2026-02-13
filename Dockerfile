# Build the manager binary
FROM docker.io/golang:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Cache deps before building
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/
COPY pkg/ pkg/

# Build — CGO disabled, stripped binary
# -ldflags="-s -w": strip debug info & symbol table for smaller image
# -trimpath: remove file system paths from binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -trimpath -ldflags="-s -w" -o manager cmd/main.go

# Use distroless as minimal base image
# [SEC] nonroot, no shell, read-only filesystem
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/openukr/openukr"
LABEL org.opencontainers.image.title="openUKR Controller"
LABEL org.opencontainers.image.description="Universal Key Rotator for Kubernetes"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
