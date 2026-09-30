# syntax=docker/dockerfile:1
#
#   docker build -t tracestate .
#   docker run --rm -v "$PWD:/src:ro" -v tracestate-ledger:/ledger tracestate scan .
#
# The image holds a static binary on distroless and runs as a non-root user.
# The ledger lives in /ledger; mount a volume there to keep it between runs.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/tracestate ./cmd/tracestate \
    && mkdir -p /out/ledger

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/tracestate /usr/local/bin/tracestate
COPY --from=build --chown=65532:65532 /out/ledger /ledger
ENV TRACESTATE_LEDGER=/ledger/tracestate-ledger.db
WORKDIR /src
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tracestate"]
CMD ["scan", "."]
