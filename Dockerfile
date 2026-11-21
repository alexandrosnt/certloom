# Build stage: reproducible, static binaries.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY client/go.mod client/
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/alexandrosnt/certloom/internal/version.Version=${VERSION} -X github.com/alexandrosnt/certloom/internal/version.Commit=${COMMIT}" \
      -o /out/ ./cmd/certloomd ./cmd/certloom

# Runtime: distroless, non-root, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certloomd /out/certloom /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/certloomd"]
CMD ["serve"]
