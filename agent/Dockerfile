# Build:  docker build -t shieldops-agent:1 agent/
# Run:    see the Docker command on the Agent tokens page (mounts / read-only at /host).
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /shieldops-agent .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /shieldops-agent /shieldops-agent
ENV SHIELDOPS_HOST_ROOT=/host
USER 65534:65534
ENTRYPOINT ["/shieldops-agent"]