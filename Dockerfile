ARG DOCKER_BUILDER_IMAGE=golang:1.21
ARG DOCKER_BASE_IMAGE=gcr.io/distroless/static:nonroot

FROM --platform=${TARGETPLATFORM} ${DOCKER_BUILDER_IMAGE} AS builder
ARG TARGETARCH
WORKDIR /chimera

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
ENV ARCH=${TARGETARCH}

RUN make build ARCH=${ARCH}

FROM --platform=${TARGETPLATFORM} ${DOCKER_BASE_IMAGE}

WORKDIR /
COPY --from=builder /chimera/LICENSE .
COPY --from=builder /chimera/html html
COPY --from=builder /chimera/static static
COPY --from=builder /chimera/build/_output/bin/chimera .

USER nonroot:nonroot

ENTRYPOINT ["/chimera"]
