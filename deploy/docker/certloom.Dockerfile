# Release image for certloomd and the certloom CLI. GoReleaser builds the
# binaries and puts them under <os>/<arch>/ in the build context; the image
# only copies them, so it carries the same bytes as the release archives.
# For a build from source use the Dockerfile at the repository root.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certloomd $TARGETPLATFORM/certloom /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/certloomd"]
CMD ["serve"]
