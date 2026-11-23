# keyref-server image (design §10.2, §12.3).
#
# Build from the repository root so the shared proto module is in context:
#   docker build -f server/Dockerfile -t keyref-server:dev .
#
# The builder writes its own go.work with only ./proto and ./server so
# the image does not depend on the CLI module.

FROM --platform=$BUILDPLATFORM oven/bun:1.4.2 AS web
WORKDIR /src/server/web
COPY server/web/package.json server/web/bun.lock ./
RUN bun install --frozen-lockfile
COPY server/web/ ./
RUN bun run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src

COPY proto/go.mod proto/go.sum ./proto/
COPY server/go.mod server/go.sum ./server/
RUN go work init ./proto ./server
WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod go mod download

WORKDIR /src
COPY proto/ ./proto/
COPY server/ ./server/
COPY --from=web /src/server/internal/accountvault/web/build/main.js ./server/internal/accountvault/web/build/main.js

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/keyref-server ./cmd/keyref-server

# /data pre-owned by the runtime user so named volumes inherit it.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keyref-server /keyref-server
COPY --from=build --chown=nonroot:nonroot /out/data /data

# KEYREF_DATA volume (default /data); 80/443 for ACME deployments.
VOLUME ["/data"]
EXPOSE 80 443
ENV KEYREF_DATA=/data

USER nonroot:nonroot
ENTRYPOINT ["/keyref-server"]
