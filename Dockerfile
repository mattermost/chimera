ARG DOCKER_BUILDER_IMAGE=golang:1.16
ARG DOCKER_BASE_IMAGE=gcr.io/distroless/static:nonroot

FROM ${DOCKER_BUILDER_IMAGE} AS builder

WORKDIR /chimera

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN make build

FROM ${DOCKER_BASE_IMAGE}

WORKDIR /
COPY --from=builder /chimera/LICENSE .
COPY --from=builder /chimera/html html
COPY --from=builder /chimera/static static
COPY --from=builder /chimera/build/_output/bin/chimera .

USER nonroot:nonroot

ENTRYPOINT ["/chimera"]
