ARG DOCKER_BUILDER_IMAGE=golang:1.20
ARG DOCKER_BASE_IMAGE=gcr.io/distroless/static:nonroot

FROM ${DOCKER_BUILDER_IMAGE} AS builder

WORKDIR /chimera

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Detect architecture and set ARCH
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ARCH="arm64"; \
    elif [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv6l" ]; then \
        ARCH="arm"; \
    fi && \
    echo "ARCH=$ARCH" && \
    make build ARCH=$ARCH

FROM ${DOCKER_BASE_IMAGE}

WORKDIR /
COPY --from=builder /chimera/LICENSE .
COPY --from=builder /chimera/html html
COPY --from=builder /chimera/static static
COPY --from=builder /chimera/build/_output/bin/chimera .

USER nonroot:nonroot

ENTRYPOINT ["/chimera"]
