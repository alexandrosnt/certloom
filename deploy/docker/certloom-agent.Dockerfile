# Release image for certloom-agent (in-cluster observation, ADR-0023). See
# certloom.Dockerfile for how the binaries get here.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certloom-agent $TARGETPLATFORM/certloom-plugin /usr/local/bin/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/certloom-agent"]
CMD ["run", "--config", "/etc/certloom-agent/config.yaml"]
